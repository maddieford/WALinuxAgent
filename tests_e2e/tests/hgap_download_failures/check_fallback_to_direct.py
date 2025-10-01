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

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIdentifier, VmExtensionIds


class CheckFallbackToDirect(AgentVmTest):
    """
    This test adds a DROP rule on outbound requests on the HGAP port and verifies that the agent falls back to the
    Direct download channel.
    """
    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # Delete all extensions on VM to reduce the amount of manifest downloads attempted in the agent after we block
        # outbound requests to HGAP port. Test will be too long if we keep all extensions in the GS.
        extensions_on_vm = self._context.vm.get_extensions().value
        for ext in extensions_on_vm:
            ext_name = ext.name
            log.info(f"Removing {ext_name}...")
            VirtualMachineExtensionClient(self._context.vm,
                                          VmExtensionIdentifier(publisher=ext.publisher,
                                                                ext_type=ext.type_properties_type,
                                                                version=ext.type_handler_version),
                                          resource_name=ext_name).delete()
            log.info(f"Deleted {ext_name}.")

        # Stop the agent service
        log.info("")
        log.info("Stopping the agent...")
        command = 'agent-service stop'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

        # Add a DROP rule for outbound requests to HGAP port
        log.info("")
        log.info("Adding DROP rule for outbound requests to HGAP port...")
        self._run_remote_test(ssh_client, "no_outbound_connections-manage_firewall_rule.py --action add", use_sudo=True)

        #  Disable FastTrack to avoid errors fetching VmSettings which would block goal state processing
        #  Disable Firewall to prevent the agent from resetting the firewall rules
        #  Restart the agent
        log.info("")
        log.info("Disabling FastTrack, firewall, and restarting the agent...")
        command = 'update-waagent-conf Debug.EnableFastTrack=n OS.EnableFirewall=n'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

        # Enable CSE and assert that it succeeds
        log.info("")
        log.info("Installing CSE...")
        custom_script = VirtualMachineExtensionClient(
            self._context.vm,
            VmExtensionIds.CustomScript)
        custom_script.enable(settings={'commandToExecute': f"echo '{str(uuid.uuid4())}'"})
        log.info("CSE succeeded as expected.")

        # Check the agent log to verify that the agent did fall back to Direct download channel
        log.info("")
        log.info("Checking agent log to verify that agent did fall back to Direct download channel...")
        expected_message = 'Default channel changed to Direct channel.'
        command = f"check_data_in_agent_log.py --data '{expected_message}'"
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))
        log.info("Found agent log indicating that the agent switched to the Direct channel.")

        # Clean up test VM so that it can be shared with other tests
        # Stop the agent service
        log.info("")
        log.info("Stopping the agent...")
        command = 'agent-service stop'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))

        # Delete DROP rule for outbound requests to HGAP port
        log.info("")
        log.info("Deleting DROP rule for outbound requests to HGAP port...")
        self._run_remote_test(ssh_client, "no_outbound_connections-manage_firewall_rule.py --action delete",
                              use_sudo=True)

        #  Re-enable FastTrack and Firewall. Restart the agent.
        log.info("")
        log.info("Re-enabling FastTrack, firewall, and restarting the agent...")
        command = 'update-waagent-conf Debug.EnableFastTrack=y OS.EnableFirewall=y'
        log.info("Remote command [%s] completed:\n%s", command, ssh_client.run_command(command, use_sudo=True))


if __name__ == "__main__":
    CheckFallbackToDirect.run_from_command_line()

