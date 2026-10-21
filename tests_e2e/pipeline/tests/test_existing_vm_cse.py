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

import contextlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from tests_e2e.tests.cse import add_cse


class TestExistingVmCse(unittest.TestCase):
    def setUp(self):
        self.vm = {"storageProfile": {"osDisk": {"osType": "Linux"}}}
        self.extension = {
            "provisioningState": "Succeeded",
            "instanceView": {
                "statuses": [{"code": "ProvisioningState/succeeded", "message": "CSE e2e test marker"}]
            }
        }
        self.az = patch.object(add_cse, "az").start()
        self.addCleanup(patch.stopall)
        patch.object(add_cse.uuid, "uuid4", return_value="marker").start()
        self.output = contextlib.ExitStack()
        self.addCleanup(self.output.close)
        self.output.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.output.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def run_cse(self, extensions=None):
        self.az.side_effect = [self.vm, extensions or [], {}, self.extension]
        add_cse.add_cse("subscription", "group", "vm")
        return self.az.call_args_list[2].args

    def test_installs_and_verifies_cse_without_guest_setup(self):
        arguments = self.run_cse()
        self.assertEqual(arguments[:3], ("vm", "extension", "set"))
        self.assertIn("--force-update", arguments)
        self.assertEqual(arguments[arguments.index("--extension-instance-name") + 1], "CustomScript")
        settings = json.loads(arguments[arguments.index("--protected-settings") + 1])
        self.assertEqual(settings, {"commandToExecute": "echo 'CSE e2e test marker'"})
        self.assertIn("--instance-view", self.az.call_args.args)
        self.assertEqual(self.az.call_count, 4)

    def test_forces_settings_update_using_existing_resource_name(self):
        for type_key in ("typePropertiesType", "type"):
            with self.subTest(type_key=type_key):
                self.az.reset_mock()
                arguments = self.run_cse([{
                    "name": "my-existing-cse",
                    "publisher": "Microsoft.Azure.Extensions",
                    type_key: "CustomScript"
                }])
                self.assertEqual(arguments[arguments.index("--extension-instance-name") + 1], "my-existing-cse")
                self.assertIn("--force-update", arguments)
                self.assertEqual(self.az.call_args.args[self.az.call_args.args.index("--name") + 1], "my-existing-cse")

    def test_refuses_ambiguous_existing_cse_resources(self):
        self.az.side_effect = [self.vm, [
            {"name": name, "publisher": add_cse.PUBLISHER, "type": "CustomScript"}
            for name in ("first-cse", "second-cse")
        ]]
        with self.assertRaisesRegex(ValueError, "Multiple"):
            add_cse.add_cse("subscription", "group", "vm")
        self.assertEqual(self.az.call_count, 2)

    def test_refuses_unrelated_extension_name_collision(self):
        self.az.side_effect = [self.vm, [{"name": "CustomScript", "publisher": "other"}]]
        with self.assertRaisesRegex(ValueError, "unrelated"):
            add_cse.add_cse("subscription", "group", "vm")
        self.assertEqual(self.az.call_count, 2)

    def test_requires_all_vm_parameters_before_accessing_azure(self):
        for target in [("-", "group", "vm"), ("subscription", "", "vm"), ("subscription", "group", " ")]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                add_cse.add_cse(*target)
        self.az.assert_not_called()

    def test_rejects_windows_before_writing(self):
        self.vm["storageProfile"]["osDisk"]["osType"] = "Windows"
        self.az.return_value = self.vm
        with self.assertRaisesRegex(ValueError, "Linux"):
            add_cse.add_cse("subscription", "group", "vm")
        self.assertEqual(self.az.call_count, 1)

    def test_rejects_unsuccessful_provisioning(self):
        self.extension["provisioningState"] = "Failed"
        with self.assertRaisesRegex(AssertionError, "provisioning"):
            self.run_cse()

    def test_rejects_missing_success_status_or_command_output(self):
        for statuses in [[], [{"code": "ProvisioningState/failed", "message": "CSE e2e test marker"}],
                         [{"code": "ProvisioningState/succeeded", "message": "old output"}]]:
            with self.subTest(statuses=statuses):
                self.extension["instanceView"]["statuses"] = statuses
                with self.assertRaises(AssertionError):
                    self.run_cse()

    def test_accepts_command_output_in_substatus(self):
        self.extension["instanceView"]["statuses"][0]["message"] = ""
        self.extension["instanceView"]["substatuses"] = [{"message": "CSE e2e test marker"}]
        self.run_cse()

    def test_azure_cli_errors_are_not_swallowed(self):
        self.az.side_effect = subprocess.CalledProcessError(1, ["az"])
        with self.assertRaises(subprocess.CalledProcessError):
            add_cse.add_cse("subscription", "group", "vm")

    def test_log_collection_discovers_ip_and_streams_archive(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(add_cse.subprocess, "run") as run:
            key = Path(directory) / "key"
            key.touch()
            output = Path(directory) / "logs.tgz"
            self.az.return_value = {"publicIps": "", "privateIps": "10.0.0.4"}
            add_cse.collect_vm_logs("subscription", "group", "vm", "-", "admin", key, output)
            command = run.call_args.args[0]
            self.assertIn("10.0.0.4", command)
            self.assertIn("admin", command)
            self.assertIn("StrictHostKeyChecking=accept-new", command)
            self.assertTrue(command[-1].startswith("sudo -n sh -c "))
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(run.call_args.kwargs["stdout"].name, str(output))

            remote_command = command[-1]
        # A sudo failure is not a tar warning; only tar's exit code 1 is tolerated.
        result = subprocess.run(["sh", "-c", "sudo() { return 1; }; " + remote_command], check=False)
        self.assertEqual(result.returncode, 1)
        tar_command = shlex.split(remote_command)[-1]
        for tar_exit_code in (0, 1, 2):
            result = subprocess.run(
                ["sh", "-c", f"tar() {{ return {tar_exit_code}; }}; " + tar_command], check=False)
            self.assertEqual(result.returncode, int(tar_exit_code > 1))

    def test_log_collection_failure_removes_incomplete_archive(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(add_cse.subprocess, "run") as run:
            key = Path(directory) / "key"
            key.touch()
            output = Path(directory) / "logs.tgz"
            run.side_effect = subprocess.CalledProcessError(255, ["ssh"])
            with self.assertRaises(subprocess.CalledProcessError):
                add_cse.collect_vm_logs("s", "g", "v", "host", "admin", key, output)
            self.assertFalse(output.exists())
            self.az.assert_not_called()

    def test_main_reports_cse_and_collection_results_separately(self):
        for mode, cse_fails, logs_fail, collected in [
                ("no", False, False, False), ("no", True, False, False),
                ("failed", False, False, False), ("failed", True, False, True),
                ("always", False, False, True), ("always", False, True, True),
                ("always", True, True, True)]:
            with self.subTest(mode=mode, cse_fails=cse_fails, logs_fail=logs_fail):
                with tempfile.TemporaryDirectory() as directory:
                    report = Path(directory) / "results.xml"
                    arguments = ["test", "--subscription", "s", "--resource-group", "g", "--vm", "v",
                                 "--junit-file", str(report), "--collect-logs", mode]
                    with patch("sys.argv", arguments), patch.object(add_cse, "add_cse") as test:
                        with patch.object(add_cse, "collect_vm_logs") as collect:
                            test.side_effect = ValueError("CSE <failed>") if cse_fails else None
                            collect.side_effect = OSError("SSH failed") if logs_fail else None
                            exit_code = add_cse.main()
                            self.assertEqual(collect.called, collected)
                    suite = ET.parse(report).getroot()
                    self.assertEqual(int(suite.get("tests")), 1 + int(collected))
                    self.assertEqual(int(suite.get("failures")), int(cse_fails) + int(collected and logs_fail))
                    self.assertEqual(exit_code, int(cse_fails or collected and logs_fail))
                    if cse_fails:
                        self.assertEqual(suite.find("testcase/failure").get("message"), "CSE <failed>")


if __name__ == "__main__":
    unittest.main()
