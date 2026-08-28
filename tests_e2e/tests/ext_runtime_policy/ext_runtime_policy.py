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

import json
import os
import uuid
from typing import Any, Dict, List

from assertpy import assert_that

from azurelinuxagent.common.utils.flexible_version import FlexibleVersion

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIdentifier


class ExtRuntimePolicy(AgentVmTest):
    """
    Validates the runtime policy feature for VM extensions:

    1. A policy-capable CSE receives a matching AllowedCommandToExecute policy and enables successfully.
    2. The agent refreshes the policy before re-enable, causing CSE to reject a command that is no longer allowed.
    3. Omitting runtimePolicy writes an empty policy, while removing the agent policy deletes the runtime policy file.
    4. Production CSE 2.0, which does not declare supportsPolicy, is blocked when runtime policy is configured.
    5. Production CSE 2.0, which does not declare supportsPolicy, is allowed when runtime policy is not configured.
    """
    # ARM accepts only major.minor for typeHandlerVersion. Request 2.8 as the minimum
    # policy-capable version.
    # TODO: Only the Test CSE Extension supports policy right now. Once the Prod CSE Extension supports policy, the
    #  publisher/type/version should be updated to use Prod
    _MINIMUM_CSE_VERSION_SUPPORTS_POLICY = FlexibleVersion("2.8.0")
    _CSE = VmExtensionIdentifier(
        publisher="Microsoft.Azure.Extensions.Edp",
        ext_type="CustomScript",
        version="2.8")

    # CSE 2.0 does not declare supportsPolicy and is used to validate that the agent does not attempt to use policy
    # with an extension that does not support it.
    _UNSUPPORTED_CSE = VmExtensionIdentifier(
        publisher="Microsoft.Azure.Extensions",
        ext_type="CustomScript",
        version="2.0")

    _SUPPORTED_EXTENSION_NAME = "{0}.{1}".format(_CSE.publisher, _CSE.type)
    _UNSUPPORTED_EXTENSION_NAME = "{0}.{1}".format(_UNSUPPORTED_CSE.publisher, _UNSUPPORTED_CSE.type)
    _POLICY_FILE = "/etc/waagent_policy.json"
    _UNSUPPORTED_EXTENSION_OUTPUT = "/tmp/unsupported-extension-executed"
    _ALLOWED_COMMAND = "echo 'Hello, world!'"

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def _create_policy_file(self, policy):
        """
        Create policy json file and copy to /etc/waagent_policy.json on test machine.
        """
        unique_id = uuid.uuid4()
        file_path = f"/tmp/waagent_policy_{unique_id}.json"
        with open(file_path, mode="w") as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            log.info(f"Policy file contents: {json.dumps(policy, indent=4)}")

            remote_path = "/tmp/waagent_policy.json"
            local_path = policy_file.name
            self._ssh_client.copy_to_node(local_path=local_path, remote_path=remote_path)
            log.info("Copying policy file to test VM [%s]", self._context.vm.name)
            self._ssh_client.run_command(f"mv {remote_path} {self._POLICY_FILE}", use_sudo=True)
        os.remove(file_path)

    def _set_runtime_policy(self, extension_name, runtime_policy=None):
        """
        Create an agent policy containing the given extension runtime policy. Pass None when the extension's
        runtimePolicy property should not be created.
        """
        extension_policy = {}
        if runtime_policy is not None:
            extension_policy["runtimePolicy"] = runtime_policy

        self._create_policy_file({
            "policyVersion": "0.1.0",
            "extensionPolicies": {
                "allowListedExtensionsOnly": False,
                "extensions": {
                    extension_name: extension_policy
                }
            }
        })

    def _enable_cse(self, extension, timeout=None):
        """
        Enable CSE, using force_update=True to ensure the extension is processed again even if settings haven't changed.
        """
        arguments = dict(
            settings={"commandToExecute": self._ALLOWED_COMMAND},
            protected_settings={},
            auto_upgrade_minor_version=True,
            force_update=True)
        if timeout is not None:
            arguments["timeout"] = timeout
        extension.enable(**arguments)

    def _assert_runtime_policy(self, runtime_policy_file_path, expected_policy):
        """
        Assert that the agent copied the expected extension policy into CSE's config directory.
        """
        actual_policy = json.loads(self._ssh_client.run_command(f"cat {runtime_policy_file_path}", use_sudo=True))
        assert_that(actual_policy).described_as("Extension runtime policy").is_equal_to(expected_policy)

    def run(self):
        cse_supports_policy = VirtualMachineExtensionClient(
            self._context.vm,
            self._CSE,
            resource_name="CustomScriptRuntimePolicy")
        cse_does_not_support_policy = VirtualMachineExtensionClient(
            self._context.vm,
            self._UNSUPPORTED_CSE,
            resource_name="UnsupportedCustomScriptRuntimePolicy")

        try:
            log.info("Enabling extension policy")
            self._ssh_client.run_command(
                "update-waagent-conf Debug.EnableExtensionPolicy=y",
                use_sudo=True)

            # A trusted extension with a matching command should receive the runtime policy and
            # execute successfully.
            log.info("Create agent policy which allows \"echo 'Hello, world!'\" command and enable CSE which supports policy")
            cse_runtime_policy = {"AllowedCommandToExecute": [self._ALLOWED_COMMAND]}
            self._set_runtime_policy(self._SUPPORTED_EXTENSION_NAME, cse_runtime_policy)
            self._enable_cse(cse_supports_policy)
            cse_supports_policy.assert_instance_view(expected_message="Hello, world!")
            instance_view = cse_supports_policy.get_instance_view()
            installed_version = FlexibleVersion(instance_view.type_handler_version)
            assert_that(installed_version >= self._MINIMUM_CSE_VERSION_SUPPORTS_POLICY) \
                .described_as("CSE must be version 2.8.0 or later") \
                .is_true()
            runtime_policy_file_path = (
                "/var/lib/waagent/{0}-{1}/config/waagent_runtime_policy.json".format(
                    self._SUPPORTED_EXTENSION_NAME,
                    instance_view.type_handler_version)
            )
            self._assert_runtime_policy(runtime_policy_file_path, cse_runtime_policy)

            # Update the agent policy to remove the allowed command and confirm CSE rejects the original command
            log.info("Refreshing runtime policy to remove the command and re-enabling CSE which supports policy which is expected to fail")
            cse_disallow_policy = {
                "AllowedCommandToExecute": []
            }
            self._set_runtime_policy(self._SUPPORTED_EXTENSION_NAME, cse_disallow_policy)

            enable_error = None
            try:
                self._enable_cse(cse_supports_policy, timeout=6 * 60)
            except Exception as error:  # pylint: disable=broad-except
                enable_error = error

            assert_that(enable_error) \
                .described_as("CSE enable error for a command blocked by runtime policy") \
                .is_not_none()
            cse_supports_policy.assert_instance_view(
                expected_status_code="ProvisioningState/failed",
                expected_message="policy-allowlist")
            self._assert_runtime_policy(runtime_policy_file_path, cse_disallow_policy)

            # When CSE remains in the agent policy but runtimePolicy is omitted, the agent must
            # replace the previous policy with {} rather than leaving the stale restrictive policy.
            log.info("Removing CSE runtimePolicy and verifying the agent writes an empty policy")
            self._set_runtime_policy(self._SUPPORTED_EXTENSION_NAME)
            self._enable_cse(cse_supports_policy)
            cse_supports_policy.assert_instance_view(expected_message="Hello, world!")
            self._assert_runtime_policy(runtime_policy_file_path, {})

            # Removing the agent policy disables enforcement. On the next enable, the agent must
            # delete CSE's stale runtime-policy file and continue processing the extension.
            log.info("Removing agent policy and verifying the stale runtime policy file is deleted")
            self._ssh_client.run_command(f"rm -f {self._POLICY_FILE}", use_sudo=True)
            self._enable_cse(cse_supports_policy)
            cse_supports_policy.assert_instance_view(expected_message="Hello, world!")
            self._ssh_client.run_command(
                f"test ! -e {runtime_policy_file_path}", use_sudo=True)

            # Runtime policy should always be applied if it exists. Remove the policy-capable CSE, then enable CSE 2.0,
            # whose manifest lacks supportsPolicy. The agent should fail the extension.
            log.info("Removing the policy-capable extension before testing an unsupported extension")
            cse_supports_policy.delete()

            log.info("Verifying runtime policy blocks an extension that does not support policy")
            unsupported_command = "touch {0}".format(self._UNSUPPORTED_EXTENSION_OUTPUT)
            self._set_runtime_policy(self._UNSUPPORTED_EXTENSION_NAME, {"AllowedCommandToExecute": [unsupported_command]})

            unsupported_enable_error = None
            try:
                cse_does_not_support_policy.enable(
                    settings={"commandToExecute": unsupported_command},
                    protected_settings={},
                    auto_upgrade_minor_version=False,
                    force_update=True,
                    timeout=6 * 60)
            except Exception as error:  # pylint: disable=broad-except
                unsupported_enable_error = error

            assert_that(unsupported_enable_error) \
                .described_as("Enable error for an extension that does not support runtime policy") \
                .is_not_none()
            cse_does_not_support_policy.assert_instance_view(
                expected_status_code="ProvisioningState/failed",
                expected_message="does not support policy enforcement")
            self._ssh_client.run_command(
                "test ! -e {0}".format(self._UNSUPPORTED_EXTENSION_OUTPUT),
                use_sudo=True)
            self._ssh_client.run_command(
                "test -z \"$(find /var/lib/waagent "
                "-path '*/Microsoft.Azure.Extensions.CustomScript-2.0*/config/waagent_runtime_policy.json' "
                "-print -quit)\"",
                use_sudo=True)

            # Without runtimePolicy, supportsPolicy is not required. The agent should enable CSE
            # normally and should not create a runtime-policy file.
            log.info("Verifying an extension that does not support policy is allowed without runtime policy")
            self._set_runtime_policy(self._UNSUPPORTED_EXTENSION_NAME)
            cse_does_not_support_policy.enable(
                settings={"commandToExecute": unsupported_command},
                protected_settings={},
                auto_upgrade_minor_version=False,
                force_update=True)
            cse_does_not_support_policy.assert_instance_view()
            self._ssh_client.run_command(
                "test -e {0}".format(self._UNSUPPORTED_EXTENSION_OUTPUT),
                use_sudo=True)
            self._ssh_client.run_command(
                "test -z \"$(find /var/lib/waagent "
                "-path '*/Microsoft.Azure.Extensions.CustomScript-2.0*/config/waagent_runtime_policy.json' "
                "-print -quit)\"",
                use_sudo=True)

            # TODO: Add multi-config coverage when an extension that supports runtime policy is available.
        finally:
            log.info("Cleaning up the runtime-policy E2E test")
            self._ssh_client.run_command(
                "rm -f {0} {1}".format(self._POLICY_FILE, self._UNSUPPORTED_EXTENSION_OUTPUT),
                use_sudo=True)

            extension_names = {item.name for item in self._context.vm.get_extensions().value}
            for extension_to_remove in [cse_supports_policy, cse_does_not_support_policy]:
                if extension_to_remove._resource_name in extension_names:
                    extension_to_remove.delete()

    def get_ignore_error_rules(self) -> List[Dict[str, Any]]:
        return [
            # CSE is expected to have failures when it rejects the command due to policy.
            {
                "message": r"commandToExecute .* policy-allowlist"
            },
            {
                "message": (
                    r"name=Microsoft.Azure.Extensions.Edp.CustomScript, op=Enable, "
                    r"message=\[ExtensionOperationError\] Non-zero exit code"
                )
            },
            # Runtime policy on an unsupported extension is intentionally rejected by the agent.
            {
                "message": (
                    r"Runtime policy is specified for extension .* "
                    r"but this extension does not support policy enforcement"
                )
            }
        ]


if __name__ == "__main__":
    ExtRuntimePolicy.run_from_command_line()
