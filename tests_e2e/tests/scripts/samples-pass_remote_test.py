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

import os
import platform
import struct
import subprocess

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
from tests_e2e.tests.lib.test_result import TestSkipped


CPUID_DEVICE = "/dev/cpu/0/cpuid"
CPUID_MODULE_PATH = "/sys/module/cpuid"
HYPERV_VENDOR_LEAF = 0x40000000
HYPERV_ISOLATION_LEAF = 0x4000000C
HYPERV_VENDOR = (0x7263694D, 0x666F736F, 0x76482074)
SNP = 0x2
TDX = 0x3


def _yes_no(value):
    return "yes" if value else "no"


def _find_executable(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        path = os.path.join(directory, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _is_cpuid_module_available():
    modinfo = _find_executable("modinfo")
    if modinfo is None:
        return False
    devnull = open(os.devnull, "w")
    try:
        return subprocess.call(
            [modinfo, "cpuid"],
            stdout=devnull,
            stderr=devnull
        ) == 0
    finally:
        devnull.close()


def _log_cpuid_state(stage):
    log.info("CPUID state %s module_present=%s module_loaded=%s device_present=%s device_readable=%s",
             stage,
             _yes_no(_is_cpuid_module_available()),
             _yes_no(os.path.isdir(CPUID_MODULE_PATH)),
             _yes_no(os.path.exists(CPUID_DEVICE)),
             _yes_no(os.access(CPUID_DEVICE, os.R_OK)))


def _load_cpuid_module():
    command = ["modprobe", "cpuid"]
    log.info("Loading the CPUID module: %s", " ".join(command))
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
    except OSError as error:
        log.info("Failed to load the CPUID module: %s", error)
        return

    stdout, stderr = process.communicate()
    if stdout:
        log.info("modprobe stdout: %s", stdout.rstrip())
    if stderr:
        log.info("modprobe stderr: %s", stderr.rstrip())
    if process.returncode != 0:
        log.info("Failed to load the CPUID module; continuing with the device read")


def _pread(descriptor, count, offset):
    if hasattr(os, "pread"):
        return os.pread(descriptor, count, offset)
    os.lseek(descriptor, offset, os.SEEK_SET)
    return os.read(descriptor, count)


def _cpuid(leaf):
    descriptor = os.open(CPUID_DEVICE, os.O_RDONLY)
    try:
        data = _pread(descriptor, 16, leaf)
    finally:
        os.close(descriptor)

    assert len(data) == 16, "Expected 16 bytes from {0}, got {1}".format(CPUID_DEVICE, len(data))
    return struct.unpack("<4I", data)


def main():
    architecture = platform.machine().lower()
    if architecture not in ("x86_64", "amd64"):
        raise TestSkipped(
            "The CPUID device is supported only on x86 systems; architecture is {0}".format(architecture)
        )

    log.info("Architecture: %s", architecture)
    log.info("Kernel: %s", platform.release())
    _log_cpuid_state("before load check:")

    if not os.path.exists(CPUID_DEVICE):
        _load_cpuid_module()

    _log_cpuid_state("after load check:")
    maximum_leaf, ebx, ecx, edx = _cpuid(HYPERV_VENDOR_LEAF)
    vendor = struct.pack("<III", ebx, ecx, edx).decode("ascii", "replace")

    log.info("Hypervisor vendor: %s", vendor)
    log.info("Maximum Hyper-V CPUID leaf: 0x%08x", maximum_leaf)
    assert (ebx, ecx, edx) == HYPERV_VENDOR, "Expected the Microsoft Hv hypervisor vendor"
    assert maximum_leaf >= HYPERV_ISOLATION_LEAF, \
        "Hyper-V isolation leaf 0x4000000C is not available"

    isolation_type = _cpuid(HYPERV_ISOLATION_LEAF)[1] & 0xF
    log.info("Hyper-V isolation type: %s", isolation_type)
    assert isolation_type in (SNP, TDX), "Expected SNP or TDX isolation, got {0}".format(isolation_type)


run_remote_test(main)
