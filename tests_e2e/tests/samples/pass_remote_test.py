#!/usr/bin/env python3

# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
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
#

from assertpy import fail

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError


class PassRemoteTest(AgentVmTest):
    """
    A lightweight test that verifies basic requirements on the remote VM.
    """
    def run(self):
        ssh_client = self._context.create_ssh_client()
        failures = []

        try:
            iptables_version = ssh_client.run_command("iptables --version", use_sudo=True).strip()
            log.info("iptables is available: %s", iptables_version)
        except CommandError:
            log.info("iptables is not available; skipping the kernel module checks")
        else:
            unresolved_modules = []
            for module_name in ["xt_owner", "xt_conntrack"]:
                try:
                    ssh_client.run_command("modinfo {0}".format(module_name), use_sudo=True)
                except CommandError as error:
                    unresolved_modules.append("{0} (exit code: {1})".format(module_name, error.exit_code))

            if len(unresolved_modules) > 0:
                failures.append(
                    "iptables is available, but modinfo could not resolve the required kernel modules: {0}".format(
                        ", ".join(unresolved_modules)))

        try:
            firewalld_state = ssh_client.run_command("firewall-cmd --state", use_sudo=True).strip()
        except CommandError:
            log.info("firewalld is not available or is not running; skipping the backend check")
        else:
            if firewalld_state == "running":
                firewalld_backend = ssh_client.run_command(
                    "firewall-cmd --get-backend", use_sudo=True).strip()
                log.info("firewalld is running with the %s backend", firewalld_backend)
                if firewalld_backend == "nftables":
                    failures.append("firewalld is running with the nftables backend")
            else:
                log.info("firewalld is present, but not running: %s", firewalld_state)

        if len(failures) > 0:
            fail("Firewall capability checks failed: {0}".format("; ".join(failures)))

        self._run_remote_test(ssh_client, "samples-pass_remote_test.py")


if __name__ == "__main__":
    PassRemoteTest.run_from_command_line()
