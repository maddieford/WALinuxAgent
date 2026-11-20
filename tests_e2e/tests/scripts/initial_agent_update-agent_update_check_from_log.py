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
# Checks that the initial agent update happens with self-update before processing goal state from the agent log

import argparse
from typing import Iterable

from assertpy import fail

from tests_e2e.tests.lib.agent_log import AgentLog, AgentLogRecord
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def verify_initial_self_update(records: Iterable[AgentLogRecord], current_version: str, latest_version: str) -> bool:
    patterns = {
        "goal_state": "ProcessExtensionsGoalState started",
        "self_update": f"Self-update is ready to upgrade the new agent: {latest_version} now before processing the goal state",
        "exit_process": f"Current Agent {current_version} completed all update checks, exiting current process to upgrade to the new Agent version {latest_version}"
    }
    first_occurrence_times = {}

    for record in records:
        for key, pattern in patterns.items():
            if key in first_occurrence_times:
                continue
            matches = record.message == pattern if key == "exit_process" else pattern in record.message
            if matches:
                log.info(f"Found data: {record} in agent log")
                first_occurrence_times[key] = record.timestamp
                break

    missing = set(patterns) - set(first_occurrence_times)
    if missing:
        log.info("Missing initial self-update log evidence: %s", sorted(missing))
        return False

    valid_order = first_occurrence_times["self_update"] <= first_occurrence_times["exit_process"] < first_occurrence_times["goal_state"]
    log.info("Initial self-update log timestamps: %s; valid order: %s", first_occurrence_times, valid_order)
    return valid_order


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--current_version", dest='current_version', required=True)
    parser.add_argument("--latest_version", dest='latest_version', required=True)
    args = parser.parse_args()

    if not retry_if_false(lambda: verify_initial_self_update(AgentLog().read(), args.current_version, args.latest_version)):
        fail("Agent log does not prove that the image agent self-updated before processing its first extensions goal state")
    log.info("Verified initial agent self-update happened before processing goal state")


if __name__ == '__main__':
    main()
