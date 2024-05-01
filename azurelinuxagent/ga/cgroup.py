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
# Requires Python 2.6+ and Openssl 1.0+

class Cgroup(object):
    def __init__(self):
        self.path = ""


class CgroupV1(Cgroup):
    def __init__(self, controller_mount_points):
        super(CgroupV1, self).__init__()
        self._controller_mount_points = controller_mount_points


class CgroupV2(Cgroup):
    def __init__(self, unified_path, enabled_controllers):
        super(CgroupV2, self).__init__()
        self._unified_path = unified_path
        self._enabled_controllers = enabled_controllers

