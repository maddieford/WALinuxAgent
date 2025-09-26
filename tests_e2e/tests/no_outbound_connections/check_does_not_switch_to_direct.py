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
import uuid
from time import sleep

from assertpy import fail
from typing import Any, Dict, List

from azurelinuxagent.common.future import ustr
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds, VmExtensionIdentifier


class CheckDoesNotSwitchToDirect(AgentVmTest):
    """
    Verifies that the agent does not switch to the direct download channel in the case of HGAP download failures on a
     VM with no outbound connection (direct download will also fail, so the agent shouldn't switch the channel).
    """
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # Delete CSE if already installed. Later in test we will attempt to install and verify that the installation
        # fails due to download failures.
        extensions_on_vm = self._context.vm.get_extensions().value
        for ext in extensions_on_vm:
            if ext.extension.type_properties_type == VmExtensionIds.CustomScript.type:
                log.info("CSE is already installed, cleaning it up...")
                VirtualMachineExtensionClient(self._context.vm,
                                              VmExtensionIdentifier(publisher=ext.extension.publisher,
                                                                    ext_type=ext.extension.type_properties_type,
                                                                    version=ext.extension.type_handler_version),
                                              resource_name=ext.extension._resource_name).delete()
                log.info("Deleted CSE.")
                break

        # Stop the agent service to add a DROP rule for outbound requests to HGAP and disable FastTrack to avoid
        # errors fetching VmSettings which would block goal state processing, and restart the agent.
        log.info("")
        log.info("Stopping the agent...")
        command = 'agent-service stop'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))
        #
        # log.info("")
        # log.info("Adding DROP rule for outbound requests to HGAP...")
        # command = 'iptables -I OUTPUT -d 168.63.129.16 -p tcp --dport 32526 -j DROP'
        # log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))
        #

        log.info("blah blah")
        self._run_remote_test(ssh_client, "no_outbound_connections-add_firewall_rule.py", use_sudo=True)

        log.info("")
        log.info("Disabling FastTrack and restarting the agent...")
        command = 'update-waagent-conf Debug.EnableFastTrack=n'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

        # Attempt to install CSE. This should fail due to failures to fetch the extension manifest (HGAP downloads will
        # fail due to drop rule and Direct downloads will fail due to no outbound connections).
        log.info("")
        log.info("Starting CSE install operation...")
        custom_script = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript)
        # The extension will fail to install due to download failures, but the agent will not be able to report
        # status due to the DROP rule and no outbound connectivity, so we set a short 30 second timeout to avoid
        # waiting for the operation to fail at the CRP level.
        timeout = 10
        start_time = ssh_client.run_command("date --utc '+%Y-%m-%dT%TZ'").rstrip()  # Record the time we enable CSE
        try:
            custom_script.enable(settings={'commandToExecute': f"echo '{str(uuid.uuid4())}'"}, timeout=timeout)
        except TimeoutError as e:
            # Timeout is expected.
            if f"[Enable Microsoft.Azure.Extensions.CustomScript] did not complete within {timeout} seconds" not in ustr(e):
                fail("Caught unexpected TimeoutError while trying to install CSE:\n%s", e)
            log.info("Test will not wait for CSE operation to finish at CRP level, as it is expected to fail due to "
                     "download failures. Will check the agent log later in test to assert that CSE failed.")
            # The agent is only fetching goal states via WireServer. Reapply the VM so that the incarnation is quickly
            # incremented.
            try:
                log.info("")
                log.info("Reapplying the VM to force new incarnation...")
                self._context.vm.reapply(timeout=timeout)
            except TimeoutError as e:
                # Timeout is expected.
                if f"[Reapply {self._context.vm.resource_group}:{self._context.vm.name}] did not complete within {timeout} seconds" not in ustr(e):
                    fail("Caught unexpected TimeoutError while trying to reapply the VM:\n%s", e)
                log.info("Test will not wait for reapply operation to finish at CRP level, as it is expected to fail "
                         "due to extension failures.")
        except Exception as e:
            fail("Caught unexpected exception while trying to install CSE:\n%s", e)

        # Check the agent log to verify that CSE failed to install due to download failures on the HGAP and direct
        # channels
        # Wait up to 15 minutes for the agent to process goal state and attempt to install CSE. There will be many
        # retries which will delay goal state processing, so we allow up to 15 minutes.
        for attempt in range(3):
            sleep(5*60)
            log.info("")
            log.info("Checking agent log to verify that CSE failed to install due to download failures on HGAP and direct channels...")
            try:
                expected_message = '.*Microsoft.Azure.Extensions.CustomScript.*\[ExtensionError\] Failed to get ext handler pkgs.*\[HttpError\] Download failed both on the primary and fallback channels'
                command = f"check_data_in_agent_log.py --after-timestamp {start_time} --data '{expected_message}'"
                log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))
                break
            except CommandError as e:
                if attempt < 2:
                    log.info("CSE has not failed, retrying in 5 minutes...")
                    continue
                else:
                    fail("Could not find agent log indicating that CSE failed:\n%s", e)

        # Check the agent log to verify that there is no log indicating that the agent switched to the direct channel
        try:
            log.info("")
            log.info("Checking agent log to verify that agent did not switch to Direct download channel...")
            unexpected_message = 'Default channel changed to Direct channel.'
            command = f"check_data_in_agent_log.py --data '{unexpected_message}'"
            log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))
            fail("Found agent log indicating that the agent switched to the Direct channel.")
        except CommandError as e:
            if 'Did not find data' not in ustr(e):
                fail("Caught unexpected exception while checking agent log:\n%s", e)
            else:
                log.info("Did not find agent log indicating that the agent switched to the Direct channel (as expected).")


    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return []


if __name__ == "__main__":
    CheckDoesNotSwitchToDirect.run_from_command_line()
