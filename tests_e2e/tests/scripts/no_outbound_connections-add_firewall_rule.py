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

from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.firewall_manager import FirewallManager


def main():
    # Add drop rule
    firewall_manager = FirewallManager.create()
    firewall_manager.create_outbound_drop_rule()


if __name__ == "__main__":
    main()
