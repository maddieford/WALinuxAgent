# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import re
from typing import Optional


def verify_image_agent_version(version_output: str, expected_version: Optional[str] = None) -> str:
    installed = re.findall(r"^WALinuxAgent-(\S+) running on .+$", version_output, re.MULTILINE)
    running = re.findall(r"^Goal state agent:[ \t]+(\S+)[ \t]*$", version_output, re.MULTILINE)
    if len(installed) != 1 or len(running) != 1:
        raise ValueError(f"Unable to determine installed and goal-state agent versions:\n{version_output}")

    # Use the image-installed version, not an already-updated goal-state handler, as the initial baseline.
    expected = installed[0] if expected_version is None else expected_version
    if installed[0] != expected or running[0] != expected:
        raise AssertionError(f"Image agent version changed: expected {expected}; installed {installed[0]}; goal-state agent {running[0]}")

    return expected
