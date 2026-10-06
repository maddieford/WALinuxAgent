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
from tests_e2e.tests.lib.test_result import TestSkipped


class CpuidModuleTest(AgentVmTest):
    """
    Checks whether the CPUID device is available and whether the cpuid module can be loaded when needed.
    """
    def run(self):
        ssh_client = self._context.create_ssh_client()
        architecture = ssh_client.get_architecture()
        if architecture not in ("x86_64", "amd64"):
            raise TestSkipped("The CPUID device is supported only on x86 systems; architecture is {0}".format(architecture))

        command = r"""
device=/dev/cpu/0/cpuid

echo "Architecture: $(uname -m)"
echo "Kernel: $(uname -r)"
echo "CPUID module present on disk: $(modinfo cpuid >/dev/null 2>&1 && echo yes || echo no)"
echo "CPUID module loaded before test: $([[ -d /sys/module/cpuid ]] && echo yes || echo no)"
echo "CPUID device present before test: $([[ -e ${device} ]] && echo yes || echo no)"
echo "CPUID device readable before test: $([[ -r ${device} ]] && echo yes || echo no)"

if [[ ! -r ${device} ]]; then
    if ! command -v modprobe >/dev/null 2>&1; then
        echo "modprobe is not available"
        exit 100
    fi

    echo "Attempting to load the cpuid module using: modprobe --use-blacklist cpuid"
    if ! modprobe --use-blacklist cpuid; then
        echo "Failed to load the cpuid module"
        exit 100
    fi

    for _ in $(seq 1 10); do
        [[ -r ${device} ]] && break
        sleep 0.2
    done
fi

echo "CPUID module loaded after check: $([[ -d /sys/module/cpuid ]] && echo yes || echo no)"
echo "CPUID device present after check: $([[ -e ${device} ]] && echo yes || echo no)"
echo "CPUID device readable after check: $([[ -r ${device} ]] && echo yes || echo no)"

if [[ ! -r ${device} ]]; then
    echo "The CPUID device is not readable after the module load check"
    exit 100
fi

python - <<'PY'
import os
import struct

device = "/dev/cpu/0/cpuid"


def cpuid(leaf):
    descriptor = os.open(device, os.O_RDONLY)
    try:
        os.lseek(descriptor, leaf, os.SEEK_SET)
        data = os.read(descriptor, 16)
    finally:
        os.close(descriptor)

    if len(data) != 16:
        raise IOError("Expected 16 bytes from {0}, got {1}".format(device, len(data)))

    return struct.unpack("<4I", data)


maximum_leaf, ebx, ecx, edx = cpuid(0x40000000)
vendor = struct.pack("<III", ebx, ecx, edx).decode("ascii", "replace")

print("Hypervisor vendor: {0}".format(vendor))
print("Maximum Hyper-V CPUID leaf: 0x{0:08x}".format(maximum_leaf))

if maximum_leaf >= 0x4000000C:
    isolation_type = cpuid(0x4000000C)[1] & 0xF
    print("Hyper-V isolation type: {0}".format(isolation_type))
else:
    print("Hyper-V isolation leaf 0x4000000C is not available")
PY
"""

        try:
            output = ssh_client.run_command(command, use_sudo=True)
        except CommandError as error:
            fail("CPUID module/device check failed: {0}".format(error))

        log.info("CPUID module/device check succeeded:\n%s", output.rstrip())


if __name__ == "__main__":
    CpuidModuleTest.run_from_command_line()
