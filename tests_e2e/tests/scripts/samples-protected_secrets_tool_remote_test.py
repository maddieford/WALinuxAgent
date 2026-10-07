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

import shutil
import subprocess

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test


SECRETS_TOOL = "azure-protected-secrets-tool"


def _is_cvm_tool():
    command = [SECRETS_TOOL, "is-cvm"]
    log.info("Executing: %s", " ".join(command))
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    stdout, stderr = process.communicate()

    if stdout:
        log.info("Tool stdout: %s", stdout.rstrip())
    if stderr:
        log.info("Tool stderr: %s", stderr.rstrip())

    if process.returncode == 0:
        return True
    if process.returncode == 1:
        return False
    raise AssertionError(
        "{0} is-cvm could not determine isolation; exit code {1}".format(SECRETS_TOOL, process.returncode)
    )


def main():
    tool = shutil.which(SECRETS_TOOL)
    assert tool is not None, "{0} is not available on PATH".format(SECRETS_TOOL)
    log.info("Fallback tool: %s", tool)

    assert _is_cvm_tool(), "{0} identified the VM as non-confidential".format(SECRETS_TOOL)
    log.info("Fallback tool identified the VM as confidential")


run_remote_test(main)
