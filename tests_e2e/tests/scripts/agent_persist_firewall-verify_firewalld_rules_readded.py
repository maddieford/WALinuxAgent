#!/usr/bin/env pypy3
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
# This script deleting the firewalld rules and ensure deleted rules added back to the firewalld rule set after agent start
#

from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.firewall_manager import FirewallManager, Firewalld, NfTables
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def verify_passthrough_rules_are_removed(firewall):
    agent_name = get_osutil().get_service_name()
    rules = [Firewalld.ACCEPT_DNS, Firewalld.ACCEPT, Firewalld.DROP]

    log.info("Stopping the agent before adding stale firewalld passthrough rules")
    shellutil.run_command(["systemctl", "stop", agent_name])

    try:
        for rule in rules:
            firewall.add_rule(rule)
            if not firewall.check_rule(rule):
                raise Exception("Failed to add the stale {0} firewalld passthrough rule".format(rule))
    finally:
        log.info("Restarting the agent to remove stale firewalld passthrough rules")
        shellutil.run_command(["systemctl", "restart", agent_name])

    rules_are_removed = retry_if_false(
        lambda: all(not firewall.check_rule(rule) for rule in rules),
        attempts=5,
        delay=30)

    if not rules_are_removed:
        raise Exception("The agent did not remove the stale firewalld passthrough rules. Current state: {0}".format(
            firewall.get_state()))

    log.info("The agent removed all stale firewalld passthrough rules")


def main():
    if not Firewalld.is_service_running():
        log.info("firewalld.service is not running and skipping test")
        return

    firewall = Firewalld()
    firewall.log_firewall_state("** firewalld.service is running; initial state of the firewall")

    if isinstance(FirewallManager.create(), NfTables):
        # Older versions of the agent always used firewalld to create passthrough rules when it is in 'running' state.
        # Newer versions of the agent do not use firewalld (even if it is in 'running' state) when NfTables is the
        # runtime firewall manager because our passthrough rules are only compatible with Iptables. The agent should
        # attempt to clean up any passthrough rules created by an old agent when NfTables is the runtime firewall
        # manager.
        verify_passthrough_rules_are_removed(firewall)
        return

    for rule in [Firewalld.ACCEPT_DNS, Firewalld.ACCEPT, Firewalld.DROP]:
        log.info(f"***** Verifying {rule} rule")
        agent_name = get_osutil().get_service_name()
        # stop the agent, so that it won't re-add rules while checking
        log.info("stop the agent, so that it won't re-add rules while checking")
        shellutil.run_command(["systemctl", "stop", agent_name])

        # deleting rule
        firewall.delete_rule(rule)
        # verifying deletion successful
        firewall.verify_rule_is_not_set(rule)

        # restart the agent to re-add the deleted rules
        log.info("restart the agent to re-add the deleted rules")
        shellutil.run_command(["systemctl", "restart", agent_name])

        firewall.assert_all_rules_are_set()


if __name__ == "__main__":
    main()
