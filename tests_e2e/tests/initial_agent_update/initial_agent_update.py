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

from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.agent_version import parse_agent_versions
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


class InitialAgentUpdate(AgentVmTest):
    """
    Verifies that the image agent self-updates before processing its first extensions goal state.
    """
    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client = self._context.create_ssh_client()
        self._test_version = ""

    def run(self):

        log.info("Testing initial self-update of the image agent without changing its code or update settings")
        version_output = self._ssh_client.run_command("waagent-version", use_sudo=True)
        self._test_version, running_version = parse_agent_versions(version_output)
        log.info("Installed image agent: %s; current goal-state agent: %s", self._test_version, running_version)

        log.info("Retrieving latest version from goal state to verify initial agent update")
        latest_version: str = self._ssh_client.run_command("agent_update-get_latest_version_from_manifest.py --family_type Prod",
                                                           use_sudo=True).rstrip()
        log.info("Latest Version: %s", latest_version)
        if FlexibleVersion(latest_version) <= FlexibleVersion(self._test_version):
            fail(f"Initial self-update requires a Prod agent newer than the installed image agent {self._test_version}; "
                 f"the region offers {latest_version}. Use a region with a newer Prod agent.")
        self._verify_agent_updated_to_latest_version(latest_version)
        self._verify_agent_updated_before_processing_goal_state(latest_version)

    def _verify_agent_updated_to_latest_version(self, latest_version: str) -> None:
        """
        Verifies the agent updated from the installed image version to the latest Prod version.
        """
        log.info("Verifying agent updated to latest version: %s from installed image version: %s", latest_version, self._test_version)
        self._verify_guest_agent_update(latest_version)

    def _verify_guest_agent_update(self, latest_version: str) -> None:
        """
        Verify current agent version running on latest version
        """

        def _check_agent_version(latest_version: str) -> bool:
            waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
            installed, running = parse_agent_versions(waagent_version)
            if installed != self._test_version:
                fail(f"Installed image agent changed: expected {self._test_version}, found {installed}")
            return running == latest_version

        log.info("Running waagent --version and checking Goal state agent version")
        success: bool = retry_if_false(lambda: _check_agent_version(latest_version), delay=60)
        waagent_version: str = self._ssh_client.run_command("waagent-version", use_sudo=True)
        if not success:
            fail("Guest agent didn't update to latest version {0} but found \n {1}".format(
                latest_version, waagent_version))
        log.info(
            f"Successfully verified agent updated to latest version. Current agent version running:\n {waagent_version}")

    def _verify_agent_updated_before_processing_goal_state(self, latest_version) -> None:
        log.info("Checking agent log if agent does initial update with self-update before processing goal state")

        self._run_remote_test(
            self._ssh_client,
            "initial_agent_update-agent_update_check_from_log.py --current_version {0} --latest_version {1}".format(self._test_version, latest_version),
            use_sudo=True)
