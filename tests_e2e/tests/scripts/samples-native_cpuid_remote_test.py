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

import binascii
import ctypes
import mmap
import platform
import struct

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.test_result import TestSkipped


CPUID_PROCESSOR_FEATURES = 0x00000001
CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS = 0x40000000
CPUID_HYPERV_INTERFACE = 0x40000001
CPUID_HYPERV_FEATURES = 0x40000003
CPUID_HYPERV_ISOLATION_CONFIG = 0x4000000C

CPUID_FEATURE_HYPERVISOR = 1 << 31
HYPERV_ISOLATION = 1 << 22
HYPERV_VENDOR_ID = b"Microsoft Hv"
HYPERV_INTERFACE_ID = b"Hv#1"

HV_ISOLATION_TYPE_MASK = 0xF
HV_ISOLATION_TYPE_SNP = 2
HV_ISOLATION_TYPE_TDX = 3


def _cpuid(eax, ecx=0):
    if not 0 <= eax <= 0xFFFFFFFF:
        raise ValueError("eax must fit in uint32")
    if not 0 <= ecx <= 0xFFFFFFFF:
        raise ValueError("ecx must fit in uint32")

    code = binascii.unhexlify(
        "53"
        "4989d0"
        "89f8"
        "89f1"
        "0fa2"
        "418900"
        "41895804"
        "41894808"
        "4189500c"
        "5b"
        "c3"
    )

    memory = mmap.mmap(
        -1,
        len(code),
        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
    )
    try:
        memory.write(code)
        result = (ctypes.c_uint32 * 4)()
        function_type = ctypes.CFUNCTYPE(
            None,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32)
        )
        function = function_type(ctypes.addressof(ctypes.c_char.from_buffer(memory)))
        function(eax, ecx, result)
        return tuple(int(value) for value in result)
    finally:
        memory.close()


def main():
    architecture = platform.machine().lower()
    if platform.system() != "Linux" or architecture not in ("x86_64", "amd64"):
        raise TestSkipped(
            "Native CPUID is supported only on Linux x86-64; platform is {0} {1}".format(
                platform.system(),
                architecture
            )
        )

    log.info("Architecture: %s", architecture)
    log.info("Kernel: %s", platform.release())
    log.info("Executing CPUID using ctypes and an executable anonymous mmap")

    _, _, processor_ecx, _ = _cpuid(CPUID_PROCESSOR_FEATURES)
    assert (processor_ecx & CPUID_FEATURE_HYPERVISOR) != 0, "The CPUID hypervisor bit is not set"

    maximum_leaf, ebx, ecx, edx = _cpuid(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS)
    vendor = struct.pack("<III", ebx, ecx, edx)
    log.info("Hypervisor vendor: %s", vendor.decode("ascii", "replace"))
    log.info("Maximum Hyper-V CPUID leaf: 0x%08x", maximum_leaf)
    assert vendor == HYPERV_VENDOR_ID, "Expected the Microsoft Hv hypervisor vendor"
    assert maximum_leaf >= CPUID_HYPERV_ISOLATION_CONFIG, \
        "Hyper-V isolation leaf 0x4000000C is not available"

    interface = struct.pack("<I", _cpuid(CPUID_HYPERV_INTERFACE)[0])
    log.info("Hyper-V interface: %s", interface.decode("ascii", "replace"))
    assert interface == HYPERV_INTERFACE_ID, "Expected the Hv#1 Hyper-V interface"

    isolation_features = _cpuid(CPUID_HYPERV_FEATURES)[1]
    assert (isolation_features & HYPERV_ISOLATION) != 0, "Hyper-V isolation is not advertised"

    isolation_type = _cpuid(CPUID_HYPERV_ISOLATION_CONFIG)[1] & HV_ISOLATION_TYPE_MASK
    log.info("Hyper-V isolation type: %s", isolation_type)
    assert isolation_type in (HV_ISOLATION_TYPE_SNP, HV_ISOLATION_TYPE_TDX), \
        "Expected SNP or TDX isolation, got {0}".format(isolation_type)

    log.info("Hyper-V confidential VM: true")


run_remote_test(main)
