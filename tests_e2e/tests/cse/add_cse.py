#!/usr/bin/env python3

# Microsoft Azure Linux Agent
#
# Copyright Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Install and verify CSE using an authenticated Azure CLI, without guest setup."""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import traceback
import uuid
import xml.etree.ElementTree as ET


PUBLISHER = "Microsoft.Azure.Extensions"
EXTENSION_TYPE = "CustomScript"


def az(*arguments):
    result = subprocess.run(
        ["az", *arguments, "--only-show-errors", "--output", "json"],
        check=True, stdout=subprocess.PIPE, text=True, timeout=1200)
    return json.loads(result.stdout)


def add_cse(subscription, resource_group, vm_name):
    for name, value in (("subId", subscription), ("rgName", resource_group), ("VMname", vm_name)):
        if not value.strip() or value.strip() == "-":
            raise ValueError(f"Provide all three existing VM parameters: {name} is missing")

    target = ["--subscription", subscription, "--resource-group", resource_group, "--name", vm_name]
    vm = az("vm", "show", *target)
    if vm["storageProfile"]["osDisk"]["osType"].lower() != "linux":
        raise ValueError("The existing VM CSE test requires a Linux VM")

    extension_target = ["--subscription", subscription, "--resource-group", resource_group, "--vm-name", vm_name]
    extensions = az("vm", "extension", "list", *extension_target)
    existing = [
        extension for extension in extensions
        if extension.get("publisher", "").lower() == PUBLISHER.lower() and
        (extension.get("typePropertiesType") or extension.get("type") or "").lower() == EXTENSION_TYPE.lower()
    ]
    if len(existing) > 1:
        raise ValueError("Multiple CSE resources found; refusing to choose which one to update")
    resource_name = existing[0]["name"] if existing else EXTENSION_TYPE
    if not existing and any(extension["name"].lower() == resource_name.lower() for extension in extensions):
        raise ValueError("An unrelated extension is named CustomScript; refusing to overwrite it")

    message = f"CSE e2e test {uuid.uuid4()}"
    print(f"Installing CSE on {resource_group}/{vm_name}; expected output: {message}", flush=True)
    az("vm", "extension", "set", *extension_target,
       "--publisher", PUBLISHER, "--name", EXTENSION_TYPE,
       "--extension-instance-name", resource_name, "--force-update",
       "--version", "2.1", "--settings", "{}",
       "--protected-settings", json.dumps({"commandToExecute": f"echo '{message}'"}))

    extension = az("vm", "extension", "show", *extension_target,
                   "--name", resource_name, "--instance-view")
    print(json.dumps(extension, indent=2), flush=True)
    if extension.get("provisioningState", "").lower() != "succeeded":
        raise AssertionError("CSE provisioning did not succeed")

    instance_view = extension.get("instanceView") or {}
    statuses = instance_view.get("statuses") or []
    if not any(status.get("code", "").lower() == "provisioningstate/succeeded" for status in statuses):
        raise AssertionError("CSE instance view did not report ProvisioningState/succeeded")

    messages = statuses + (instance_view.get("substatuses") or [])
    if not any(message in (status.get("message") or "") for status in messages):
        raise AssertionError("CSE instance view did not include the expected command output")
    print("CSE succeeded and will remain installed. The VM and agent were not replaced.", flush=True)


def collect_vm_logs(subscription, resource_group, vm_name, ssh_host, ssh_user, identity_file, output_path):
    if ssh_host == "-":
        vm = az("vm", "show", "--subscription", subscription, "--resource-group", resource_group,
                "--name", vm_name, "--show-details")
        ssh_host = vm.get("publicIps") or vm.get("privateIps") or ""
        ssh_host = ssh_host.split(",")[0].strip()
    try:
        ipaddress.ip_address(ssh_host)
    except ValueError:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]*", ssh_host):
            raise ValueError("Provide a valid SSH host or a VM with a reachable IP address") from None
    if not ssh_user.strip() or ssh_user == "-":
        raise ValueError("Provide the VM's SSH username")
    identity_file = Path(identity_file)
    if not identity_file.is_file():
        raise ValueError("An SSH private key is required to collect VM logs")
    identity_file.chmod(0o600)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Stream a root-readable archive directly to the runner; install nothing on the VM.
    command = (
        'set --; for path in /var/log /var/lib/waagent /etc/waagent.conf; do '
        'if [ -e "$path" ]; then set -- "$@" "$path"; fi; done; '
        '[ "$#" -gt 0 ] || exit 1; '
        "tar --exclude='journal/*' --exclude='*.zip' --exclude='*.deb' "
        "--exclude='*.rpm' --warning=no-file-changed -czf - "
        '"$@"; result=$?; [ "$result" -le 1 ]'
    )
    print(f"Collecting VM logs from {ssh_host} to {output_path}", flush=True)
    try:
        with output_path.open("wb") as archive:
            subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                 "-o", "ConnectTimeout=30", "-i", str(identity_file), "-l", ssh_user,
                 "--", ssh_host, "sudo -n sh -c " + shlex.quote(command)],
                check=True, stdout=archive, timeout=300)
    except (subprocess.SubprocessError, OSError):
        output_path.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--vm", required=True)
    parser.add_argument("--junit-file", required=True, type=Path)
    parser.add_argument("--collect-logs", choices=("always", "failed", "no"), default="no")
    parser.add_argument("--ssh-host", default="-")
    parser.add_argument("--ssh-user", default="waagent")
    parser.add_argument("--identity-file", default="")
    args = parser.parse_args()

    suite = ET.Element("testsuite", name="ExistingVmCse", tests="1", failures="0")
    case = ET.SubElement(suite, "testcase", classname="ExistingVmCse", name="AddCse")
    start = time.monotonic()
    exit_code = 0
    try:
        add_cse(args.subscription, args.resource_group, args.vm)
    except Exception as error:  # Report failures to both the pipeline log and JUnit.
        traceback.print_exc()
        suite.set("failures", "1")
        ET.SubElement(case, "failure", message=str(error), type=type(error).__name__).text = traceback.format_exc()
        exit_code = 1
    case.set("time", str(time.monotonic() - start))
    if args.collect_logs == "always" or args.collect_logs == "failed" and exit_code != 0:
        suite.set("tests", "2")
        log_case = ET.SubElement(suite, "testcase", classname="ExistingVmCse", name="CollectVmLogs")
        log_start = time.monotonic()
        try:
            collect_vm_logs(args.subscription, args.resource_group, args.vm, args.ssh_host,
                            args.ssh_user, args.identity_file, args.junit_file.parent / "vm-logs.tgz")
        except Exception as error:  # Log collection must not hide the original test result.
            traceback.print_exc()
            suite.set("failures", str(int(suite.get("failures")) + 1))
            ET.SubElement(log_case, "failure", message=str(error), type=type(error).__name__).text = traceback.format_exc()
            exit_code = 1
        log_case.set("time", str(time.monotonic() - log_start))
    suite.set("time", str(time.monotonic() - start))
    args.junit_file.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(args.junit_file, encoding="utf-8", xml_declaration=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
