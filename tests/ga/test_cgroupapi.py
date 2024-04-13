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
# Requires Python 2.4+ and Openssl 1.0+
#

from __future__ import print_function

import os
import re
import subprocess
import tempfile

from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.ga.cgroupapi import SystemdCgroupApiv1, SystemdCgroupApiv2, CGroupUtil, get_cgroup_api, \
    InvalidCgroupMountpointException
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.utils import fileutil
from tests.lib.mock_cgroup_environment import mock_cgroup_v1_environment, mock_cgroup_v2_environment, \
    mock_cgroup_hybrid_environment
from tests.lib.mock_environment import MockCommand
from tests.lib.tools import AgentTestCase, patch, mock_sleep
from tests.lib.cgroups_tools import CGroupsTools


class _MockedFileSystemTestCase(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)

        self.cgroups_file_system_root = os.path.join(self.tmp_dir, "cgroup")
        os.mkdir(self.cgroups_file_system_root)
        os.mkdir(os.path.join(self.cgroups_file_system_root, "cpu"))
        os.mkdir(os.path.join(self.cgroups_file_system_root, "memory"))

        self.mock_cgroups_file_system_root = patch("azurelinuxagent.ga.cgroupapi.CGROUP_FILE_SYSTEM_ROOT", self.cgroups_file_system_root)
        self.mock_cgroups_file_system_root.start()

    def tearDown(self):
        self.mock_cgroups_file_system_root.stop()
        AgentTestCase.tearDown(self)


class CGroupUtilTestCase(AgentTestCase):
    def test_cgroups_should_be_supported_only_on_ubuntu16_centos7dot4_redhat7dot4_and_later_versions(self):
        test_cases = [
            (['ubuntu', '16.04', 'xenial'], True),
            (['ubuntu', '16.10', 'yakkety'], True),
            (['ubuntu', '18.04', 'bionic'], True),
            (['ubuntu', '18.10', 'cosmic'], True),
            (['ubuntu', '20.04', 'focal'], True),
            (['ubuntu', '20.10', 'groovy'], True),
            (['centos', '7.4', 'Source'], False),
            (['redhat', '7.4', 'Maipo'], False),
            (['centos', '7.5', 'Source'], False),
            (['centos', '7.3', 'Maipo'], False),
            (['redhat', '7.2', 'Maipo'], False),
            (['centos', '7.8', 'Source'], False),
            (['redhat', '7.8', 'Maipo'], False),
            (['redhat', '7.9.1908', 'Core'], False),
            (['centos', '8.1', 'Source'], True),
            (['redhat', '8.2', 'Maipo'], True),
            (['redhat', '8.2.2111', 'Core'], True),
            (['redhat', '9.1', 'Core'], False),
            (['centos', '9.1', 'Source'], False),
            (['bigip', '15.0.1', 'Final'], False),
            (['gaia', '273.562', 'R80.30'], False),
            (['debian', '9.1', ''], False),
        ]

        for (distro, supported) in test_cases:
            with patch("azurelinuxagent.ga.cgroupapi.get_distro", return_value=distro):
                self.assertEqual(CGroupUtil.cgroups_supported(), supported, "cgroups_supported() failed on {0}".format(distro))

                
class SystemdCgroupsApiTestCase(AgentTestCase):
    def test_get_cgroup_api_raises_exception_when_systemd_mount_point_does_not_exist(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            # Mock os.path.exists to return False for the os.path.exists(CGROUP_FILE_SYSTEM_ROOT) check
            with patch("os.path.exists", return_value=False):
                with self.assertRaises(InvalidCgroupMountpointException) as context:
                    get_cgroup_api()
                self.assertTrue("Expected cgroup filesystem to be mounted at '/sys/fs/cgroup', but it is not" in str(context.exception))

    def test_get_cgroup_api_is_v2_when_v2_in_use(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            self.assertIsInstance(get_cgroup_api(), SystemdCgroupApiv2)

    def test_get_cgroup_api_raises_exception_when_hybrid_in_use_and_controllers_available_in_unified_hierarchy(self):
        with mock_cgroup_hybrid_environment(self.tmp_dir):
            # Mock /sys/fs/cgroup/unified/cgroup.controllers file to have available controllers
            with patch("os.path.exists", return_value=True):
                with patch('azurelinuxagent.common.utils.fileutil.read_file', return_value="cpu memory"):
                    with self.assertRaises(CGroupsException) as context:
                        get_cgroup_api()
                    self.assertTrue("Detected hybrid cgroup mode, but there are controllers available to be enabled in unified hierarchy: cpu memory" in str(context.exception))

    def test_get_cgroup_api_raises_exception_when_v1_in_use_and_controllers_have_non_sytemd_mountpoints(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            # Mock /sys/fs/cgroup/unified/cgroup.controllers file to have available controllers
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1.are_mountpoints_systemd_created', return_value=False):
                with self.assertRaises(InvalidCgroupMountpointException) as context:
                    get_cgroup_api()
                self.assertTrue("Expected cgroup controllers to be mounted at '/sys/fs/cgroup', but at least one is not." in str(context.exception))

    def test_get_cgroup_api_is_v1_when_v1_in_use(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            self.assertIsInstance(get_cgroup_api(), SystemdCgroupApiv1)

    def test_get_cgroup_api_is_v1_when_hybrid_in_use(self):
        with mock_cgroup_hybrid_environment(self.tmp_dir):
            # Mock os.path.exists to return True for the os.path.exists('/sys/fs/cgroup/cgroup.controllers') check
            with patch("os.path.exists", return_value=True):
                self.assertIsInstance(get_cgroup_api(), SystemdCgroupApiv1)

    def test_get_cgroup_api_raises_exception_when_cgroup_mode_cannot_be_determined(self):
        unknown_cgroup_type = "unknown_cgroup_type"
        with patch('azurelinuxagent.common.utils.shellutil.run_command', return_value=unknown_cgroup_type):
            with self.assertRaises(CGroupsException) as context:
                get_cgroup_api()
            self.assertTrue("/sys/fs/cgroup has an unexpected file type: {0}".format(unknown_cgroup_type) in str(context.exception))

    def test_get_systemd_version_should_return_a_version_number(self):
        # We expect same behavior for v1 and v2
        mock_envs = [mock_cgroup_v1_environment(self.tmp_dir), mock_cgroup_v2_environment(self.tmp_dir)]
        for env in mock_envs:
            with env:
                version_info = systemd.get_version()
                found = re.search(r"systemd \d+", version_info) is not None
                self.assertTrue(found, "Could not determine the systemd version: {0}".format(version_info))

    def test_get_unit_property_should_return_the_value_of_the_given_property(self):
        # We expect same behavior for v1 and v2
        mock_envs = [mock_cgroup_v1_environment(self.tmp_dir), mock_cgroup_v2_environment(self.tmp_dir)]
        for env in mock_envs:
            with env:
                cpu_accounting = systemd.get_unit_property("walinuxagent.service", "CPUAccounting")

                self.assertEqual(cpu_accounting, "no", "Property {0} of {1} is incorrect".format("CPUAccounting", "walinuxagent.service"))


class SystemdCgroupsApiv1TestCase(AgentTestCase):
    def test_get_unit_cgroup_paths_should_return_the_cgroup_v1_mount_points(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            unit_cgroup_paths = get_cgroup_api().get_unit_cgroup_paths("extension.service")
            self.assertEquals(unit_cgroup_paths.get('cpu,cpuacct'), '/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service',
                          "The mount point for the CPU controller is incorrect")
            self.assertEquals(unit_cgroup_paths.get('memory'), '/sys/fs/cgroup/memory/system.slice/extension.service',
                          "The mount point for the memory controller is incorrect")
            self.assertEqual(len(unit_cgroup_paths), 2, "Cpu and memory should be the only controllers tracked")

    def test_get_unit_cgroup_paths_should_only_include_mounted_controllers_v1(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1.get_controller_root_paths', return_value={'cpu,cpuacct': '/sys/fs/cgroup/cpu,cpuacct'}):
                unit_cgroup_paths = get_cgroup_api().get_unit_cgroup_paths("extension.service")
                self.assertEquals(unit_cgroup_paths.get('cpu,cpuacct'), '/sys/fs/cgroup/cpu,cpuacct/system.slice/extension.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertIsNone(unit_cgroup_paths.get('memory'),
                                  "There should not be a cgroup path for memory, since memory controller is not mounted")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1.get_controller_root_paths', return_value={'memory': '/sys/fs/cgroup/memory'}):
                unit_cgroup_paths = get_cgroup_api().get_unit_cgroup_paths("extension.service")
                self.assertIsNone(unit_cgroup_paths.get('cpu,cpuacct'), "There should not be a cgroup path for cpu, since cpu controller is not mounted")
                self.assertEquals(unit_cgroup_paths.get('memory'), '/sys/fs/cgroup/memory/system.slice/extension.service',
                              "The mount point for the memory controller is incorrect")

    def test_get_process_cgroup_paths_should_return_the_cgroup_v1_mount_points(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            process_cgroup_paths = get_cgroup_api().get_process_cgroup_paths("self")
            self.assertEquals(process_cgroup_paths.get('cpu,cpuacct'), '/sys/fs/cgroup/cpu,cpuacct/system.slice/walinuxagent.service',
                          "The mount point for the CPU controller is incorrect")
            self.assertEquals(process_cgroup_paths.get('memory'), '/sys/fs/cgroup/memory/system.slice/walinuxagent.service',
                          "The mount point for the memory controller is incorrect")
            self.assertEqual(len(process_cgroup_paths), 2, "Cpu and memory should be the only controllers tracked")

    def test_get_process_cgroup_paths_should_only_include_mounted_controllers_v1(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1.get_controller_root_paths', return_value={'cpu,cpuacct': '/sys/fs/cgroup/cpu,cpuacct'}):
                process_cgroup_paths = get_cgroup_api().get_process_cgroup_paths("self")
                self.assertEquals(process_cgroup_paths.get('cpu,cpuacct'), '/sys/fs/cgroup/cpu,cpuacct/system.slice/walinuxagent.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertIsNone(process_cgroup_paths.get('memory'),
                                  "There should not be a cgroup path for memory, since memory controller is not mounted")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1.get_controller_root_paths', return_value={'memory': '/sys/fs/cgroup/memory'}):
                process_cgroup_paths = get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIsNone(process_cgroup_paths.get('cpu,cpuacct'), "There should not be a cgroup path for cpu, since cpu controller is not mounted")
                self.assertEquals(process_cgroup_paths.get('memory'), '/sys/fs/cgroup/memory/system.slice/walinuxagent.service',
                              "The mount point for the memory controller is incorrect")

    def test_get_process_cgroup_v1_path_should_only_include_controllers_with_relative_paths_v1(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1.get_process_cgroup_relative_paths', return_value={'cpu,cpuacct': 'system.slice/walinuxagent.service'}):
                process_cgroup_paths = get_cgroup_api().get_process_cgroup_paths("self")
                self.assertEquals(process_cgroup_paths.get('cpu,cpuacct'), '/sys/fs/cgroup/cpu,cpuacct/system.slice/walinuxagent.service',
                              "The mount point for the CPU controller is incorrect")
                self.assertIsNone(process_cgroup_paths.get('memory'),
                                  "There should not be a cgroup path for memory, since the memory controller does not have a relative path")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1.get_process_cgroup_relative_paths', return_value={'memory': 'system.slice/walinuxagent.service'}):
                process_cgroup_paths = get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIsNone(process_cgroup_paths.get('cpu,cpuacct'), "There should not be a cgroup path for cpu, since the cpu controller does not have a relative path")
                self.assertEquals(process_cgroup_paths.get('memory'), '/sys/fs/cgroup/memory/system.slice/walinuxagent.service',
                              "The mount point for the memory controller is incorrect")

    def test_get_controller_root_paths_should_return_the_cgroup_v1_controller_mount_points(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            controller_root_paths = get_cgroup_api().get_controller_root_paths()
            self.assertEquals(controller_root_paths.get('cpu,cpuacct'), '/sys/fs/cgroup/cpu,cpuacct', "The root cgroup for the CPU controller is incorrect")
            self.assertEquals(controller_root_paths.get('memory'), '/sys/fs/cgroup/memory', "The root cgroup for the memory controller is incorrect")
            self.assertEqual(len(controller_root_paths), 2, "Cpu and memory should be the only controllers tracked")

    def test_get_controller_root_paths_should_only_include_mounted_controllers_v1(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1._get_controller_mountpoints', return_value={'memory': '/sys/fs/cgroup/memory'}):
                controller_root_paths = get_cgroup_api().get_controller_root_paths()
                self.assertIsNone(controller_root_paths.get('cpu,cpuacct'), "There should not be a root path for cpu, since the cpu controller is mot mounted.")
                self.assertEquals(controller_root_paths.get('memory'), '/sys/fs/cgroup/memory', "The root cgroup for the memory controller is incorrect")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1._get_controller_mountpoints', return_value={'cpu,cpuacct': '/sys/fs/cgroup/cpu,cpuacct'}):
                controller_root_paths = get_cgroup_api().get_controller_root_paths()
                self.assertIsNone(controller_root_paths.get('memory'), "There should not be a root path for memory, since the memory controller is mot mounted.")
                self.assertEqual(controller_root_paths.get('cpu,cpuacct'), '/sys/fs/cgroup/cpu,cpuacct', "The root cgroup for the cpu controller is incorrect")

    def test_get_controller_mountpoints_should_return_only_agent_cgroup_mount_points(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            cgroup_api = get_cgroup_api()
            # Expected value comes from findmnt output in the mocked environment
            self.assertEqual(cgroup_api._get_controller_mountpoints(), {
                'cpu,cpuacct': '/sys/fs/cgroup/cpu,cpuacct',
                'memory': '/sys/fs/cgroup/memory'
            }, "The controller mountpoints are not correct")

    def test_are_mountpoints_systemd_created_should_return_False_if_cpu_or_memory_are_not_systemd_mountpoints(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1._get_controller_mountpoints', return_value={'cpu,cpuacct': '/custom/mountpoint/path', 'memory': '/custom/mountpoint/path'}):
                self.assertFalse(SystemdCgroupApiv1().are_mountpoints_systemd_created())

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1._get_controller_mountpoints', return_value={'cpu,cpuacct': '/custom/mountpoint/path'}):
                self.assertFalse(SystemdCgroupApiv1().are_mountpoints_systemd_created())

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1._get_controller_mountpoints', return_value={'memory': '/custom/mountpoint/path'}):
                self.assertFalse(SystemdCgroupApiv1().are_mountpoints_systemd_created())

    def test_are_mountpoints_systemd_created_should_return_True_if_cpu_and_memory_are_systemd_mountpoints(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1._get_controller_mountpoints', return_value={'cpu,cpuacct': '/sys/fs/cgroup', 'memory': '/sys/fs/cgroup'}):
                self.assertFalse(SystemdCgroupApiv1().are_mountpoints_systemd_created())

            # are_mountpoints_systemd_created should only check controllers which are mounted
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1._get_controller_mountpoints', return_value={'cpu,cpuacct': '/sys/fs/cgroup'}):
                self.assertFalse(SystemdCgroupApiv1().are_mountpoints_systemd_created())

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv1._get_controller_mountpoints', return_value={'memory': '/sys/fs/cgroup'}):
                self.assertFalse(SystemdCgroupApiv1().are_mountpoints_systemd_created())

    def test_get_cpu_and_memory_cgroup_relative_paths_for_process_should_return_the_cgroup_v1_relative_paths(self):
        with mock_cgroup_v1_environment(self.tmp_dir):
            process_relative_paths = get_cgroup_api().get_process_cgroup_relative_paths('self')
            self.assertEquals(process_relative_paths.get('cpu,cpuacct'), "system.slice/walinuxagent.service", "The relative path for the CPU cgroup is incorrect")
            self.assertEquals(process_relative_paths.get('memory'), "system.slice/walinuxagent.service", "The relative memory for the CPU cgroup is incorrect")
            self.assertEqual(len(process_relative_paths), 2, "Cpu and memory should be the only controllers tracked")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_cgroups_v1_command_should_return_the_command_output(self, _):
        with mock_cgroup_v1_environment(self.tmp_dir):
            original_popen = subprocess.Popen

            def mock_popen(command, *args, **kwargs):
                if isinstance(command, str) and command.startswith('systemd-run --property'):
                    command = "echo TEST_OUTPUT"
                return original_popen(command, *args, **kwargs)

            with tempfile.TemporaryFile(dir=self.tmp_dir, mode="w+b") as output_file:
                with patch("subprocess.Popen",
                           side_effect=mock_popen) as popen_patch:  # pylint: disable=unused-variable
                    command_output = get_cgroup_api().start_extension_command(
                        extension_name="Microsoft.Compute.TestExtension-1.2.3",
                        command="A_TEST_COMMAND",
                        cmd_name="test",
                        shell=True,
                        timeout=300,
                        cwd=self.tmp_dir,
                        env={},
                        stdout=output_file,
                        stderr=output_file)

                    self.assertIn("[stdout]\nTEST_OUTPUT\n", command_output, "The test output was not captured")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_cgroups_v1_command_should_execute_the_command_in_a_cgroup(self, _):
        with mock_cgroup_v1_environment(self.tmp_dir):
            get_cgroup_api().start_extension_command(
                extension_name="Microsoft.Compute.TestExtension-1.2.3",
                command="test command",
                cmd_name="test",
                shell=False,
                timeout=300,
                cwd=self.tmp_dir,
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            tracked = CGroupsTelemetry._tracked

            self.assertTrue(
                any(cg for cg in tracked.values() if
                    cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and '/sys/fs/cgroup/cpu,cpuacct' in cg.path),
                "The extension's CPU is not being tracked")

            self.assertTrue(
                any(cg for cg in tracked.values() if
                    cg.name == 'Microsoft.Compute.TestExtension-1.2.3' and '/sys/fs/cgroup/memory' in cg.path),
                "The extension's Memory is not being tracked")

    @patch('time.sleep', side_effect=lambda _: mock_sleep())
    def test_start_extension_cgroups_v1_command_should_use_systemd_to_execute_the_command(self, _):
        with mock_cgroup_v1_environment(self.tmp_dir):
            with patch("subprocess.Popen", wraps=subprocess.Popen) as popen_patch:
                get_cgroup_api().start_extension_command(
                    extension_name="Microsoft.Compute.TestExtension-1.2.3",
                    command="the-test-extension-command",
                    cmd_name="test",
                    timeout=300,
                    shell=True,
                    cwd=self.tmp_dir,
                    env={},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                extension_calls = [args[0] for (args, _) in popen_patch.call_args_list if
                                   "the-test-extension-command" in args[0]]

                self.assertEqual(1, len(extension_calls), "The extension should have been invoked exactly once")
                self.assertIn("systemd-run", extension_calls[0], "The extension should have been invoked using systemd")


class SystemdCgroupsApiv2TestCase(AgentTestCase):
    def test_get_controllers_enabled_at_root_should_return_list_of_enabled_controllers(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            cgroup_api = get_cgroup_api()
            self.assertEqual(cgroup_api._get_controllers_enabled_at_root('/sys/fs/cgroup'), ['cpuset', 'cpu', 'io', 'memory', 'pids'])

    def test_get_controllers_enabled_at_root_should_return_empty_list_if_root_cgroup_path_is_empty(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv2._get_root_cgroup_path', return_value=""):
                cgroup_api = get_cgroup_api()
                self.assertEqual(cgroup_api._controllers_enabled_at_root, [])

    def test_get_root_cgroup_path_should_return_v2_cgroup_root(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            cgroup_api = get_cgroup_api()
            self.assertEqual(cgroup_api._get_root_cgroup_path(), '/sys/fs/cgroup')

    def test_get_root_cgroup_path_should_only_match_systemd_mountpoint(self):
        with mock_cgroup_v2_environment(self.tmp_dir) as env:
            # Mock an environment which has multiple v2 mountpoints
            env.add_command(MockCommand(r"^findmnt -t cgroup2 --noheadings$",
'''/custom/mountpoint/path1 cgroup2 cgroup2 rw,relatime
/sys/fs/cgroup           cgroup2 cgroup2 rw,nosuid,nodev,noexec,relatime
/custom/mountpoint/path2 none    cgroup2 rw,relatime
'''))
            cgroup_api = get_cgroup_api()
            self.assertEqual(cgroup_api._get_root_cgroup_path(), '/sys/fs/cgroup')

    def test_get_unit_cgroup_paths_should_return_the_cgroup_v2_cgroup_paths(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            unit_cgroup_paths = get_cgroup_api().get_unit_cgroup_paths("extension.service")
            self.assertEquals(unit_cgroup_paths.get('cpu'), '/sys/fs/cgroup/system.slice/extension.service',
                          "The cgroup path for the CPU controller is incorrect")
            self.assertEquals(unit_cgroup_paths.get('memory'), '/sys/fs/cgroup/system.slice/extension.service',
                        "The cgroup path for the memory controller is incorrect")
            self.assertEqual(len(unit_cgroup_paths), 2, "Cpu and memory should be the only controllers tracked")

    def test_get_unit_cgroup_paths_should_only_include_enabled_controllers_v2(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv2.get_controller_root_paths', return_value={'cpu': '/sys/fs/cgroup'}):
                unit_cgroup_paths = get_cgroup_api().get_unit_cgroup_paths("extension.service")
                self.assertEquals(unit_cgroup_paths.get('cpu'), '/sys/fs/cgroup/system.slice/extension.service',
                              "The cgroup path for the CPU controller is incorrect")
                self.assertIsNone(unit_cgroup_paths.get('memory'),
                                  "There should not be a cgroup path for memory, since memory controller is not enabled")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv2.get_controller_root_paths', return_value={'memory': '/sys/fs/cgroup'}):
                unit_cgroup_paths = get_cgroup_api().get_unit_cgroup_paths("extension.service")
                self.assertIsNone(unit_cgroup_paths.get('cpu'), "There should not be a cgroup path for cpu, since cpu controller is not enabled")
                self.assertEquals(unit_cgroup_paths.get('memory'), '/sys/fs/cgroup/system.slice/extension.service',
                              "The cgroup path for the memory controller is incorrect")

    def test_get_process_cgroup_paths_should_return_the_cgroup_v2_cgroup_paths(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            process_cgroup_paths = get_cgroup_api().get_process_cgroup_paths("self")
            self.assertEquals(process_cgroup_paths.get('cpu'), '/sys/fs/cgroup/system.slice/walinuxagent.service',
                          "The cgroup path for the CPU controller is incorrect")
            self.assertEquals(process_cgroup_paths.get('memory'), '/sys/fs/cgroup/system.slice/walinuxagent.service',
                          "The cgroup path for the memory controller is incorrect")
            self.assertEqual(len(process_cgroup_paths), 2, "Cpu and memory should be the only controllers tracked")

    def test_get_process_cgroup_paths_should_only_include_enabled_controllers_v2(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv2.get_controller_root_paths', return_value={'cpu': '/sys/fs/cgroup'}):
                process_cgroup_paths = get_cgroup_api().get_process_cgroup_paths("self")
                self.assertEquals(process_cgroup_paths.get('cpu'), '/sys/fs/cgroup/system.slice/walinuxagent.service',
                              "The cgroup path for the CPU controller is incorrect")
                self.assertIsNone(process_cgroup_paths.get('memory'),
                                  "TThere should not be a cgroup path for memory, since memory controller is not enabled")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv2.get_controller_root_paths', return_value={'memory': '/sys/fs/cgroup'}):
                process_cgroup_paths = get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIsNone(process_cgroup_paths.get('cpu'), "There should not be a cgroup path for cpu, since cpu controller is not enabled")
                self.assertEquals(process_cgroup_paths.get('memory'), '/sys/fs/cgroup/system.slice/walinuxagent.service',
                              "The cgroup path for the memory controller is incorrect")

    def test_get_process_cgroup_v2_paths_should_only_include_controllers_with_relative_paths_v2(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv2.get_process_cgroup_relative_paths', return_value={}):
                process_cgroup_paths = get_cgroup_api().get_process_cgroup_paths("self")
                self.assertIsNone(process_cgroup_paths.get('cpu'), "There should not be a cgroup path for cpu, since the cpu controller does not have a relative path")
                self.assertIsNone(process_cgroup_paths.get('memory'),
                                  "There should not be a cgroup path for memory, since the memory controller does not have a relative path")

    def test_get_controller_root_paths_should_return_the_cgroup_v2_root_cgroup_path(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            controller_root_paths = get_cgroup_api().get_controller_root_paths()
            self.assertEquals(controller_root_paths.get('cpu'), '/sys/fs/cgroup', "The root cgroup for the CPU controller is incorrect")
            self.assertEquals(controller_root_paths.get('memory'), '/sys/fs/cgroup', "The root cgroup for the memory controller is incorrect")
            self.assertEqual(len(controller_root_paths), 2, "Cpu and memory should be the only controllers tracked")

    def test_get_controller_root_paths_should_return_empty_if_root_cgroup_path_is_empty(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv2._get_root_cgroup_path', return_value=""):
                controller_root_paths = get_cgroup_api().get_controller_root_paths()
                self.assertIsNone(controller_root_paths.get('cpu'), "The root cgroup path is empty, so no controllers should have root paths")
                self.assertIsNone(controller_root_paths.get('memory'), "The root cgroup path is empty, so no controllers should have root paths")
                self.assertEqual(len(controller_root_paths), 0, "No controllers should be tracked if root cgroup path is empty")

    def test_get_controller_root_paths_should_only_include_enabled_agent_cgroup_controllers(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv2._get_controllers_enabled_at_root', return_value=['io', 'memory']):
                controller_root_paths = get_cgroup_api().get_controller_root_paths()
                self.assertIsNone(controller_root_paths.get('cpu'), "There should not be a cpu cgroup path, since the cpu controller is not enabled")
                self.assertEquals(controller_root_paths.get('memory'), '/sys/fs/cgroup', "The root cgroup for the memory controller is incorrect")
                self.assertEqual(len(controller_root_paths), 1, "The only agent cgroup controller which is enabled is memory")

            with patch('azurelinuxagent.ga.cgroupapi.SystemdCgroupApiv2._get_controllers_enabled_at_root', return_value=['cpu', 'io']):
                controller_root_paths = get_cgroup_api().get_controller_root_paths()
                self.assertEquals(controller_root_paths.get('cpu'), '/sys/fs/cgroup', "The root cgroup for the CPU controller is incorrect")
                self.assertIsNone(controller_root_paths.get('memory'), "There should not be a memory cgroup path, since the memory controller is not enabled")
                self.assertEqual(len(controller_root_paths), 1, "The only agent cgroup controller which is enabled is cpu")

    def test_get_cpu_and_memory_cgroup_relative_paths_for_process_should_return_the_cgroup_v2_relative_paths(self):
        with mock_cgroup_v2_environment(self.tmp_dir):
            controller_root_paths = get_cgroup_api().get_process_cgroup_relative_paths('self')
            self.assertEquals(controller_root_paths.get('cpu'), "system.slice/walinuxagent.service", "The relative path for the CPU cgroup is incorrect")
            self.assertEquals(controller_root_paths.get('memory'), "system.slice/walinuxagent.service", "The relative memory for the CPU cgroup is incorrect")
            self.assertEqual(len(controller_root_paths), 2, "Cpu and memory should be the only controllers tracked")


class SystemdCgroupsApiMockedFileSystemTestCase(_MockedFileSystemTestCase):
    def test_cleanup_legacy_cgroups_should_remove_legacy_cgroups(self):
        # Set up a mock /var/run/waagent.pid file
        daemon_pid_file = os.path.join(self.tmp_dir, "waagent.pid")
        fileutil.write_file(daemon_pid_file, "42\n")

        # Set up old controller cgroups, but do not add the daemon's PID to them
        legacy_cpu_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "cpu", '')
        legacy_memory_cgroup = CGroupsTools.create_legacy_agent_cgroup(self.cgroups_file_system_root, "memory", '')

        with patch("azurelinuxagent.ga.cgroupapi.get_agent_pid_file_path", return_value=daemon_pid_file):
            legacy_cgroups = CGroupUtil.cleanup_legacy_cgroups()

        self.assertEqual(legacy_cgroups, 2, "cleanup_legacy_cgroups() did not find all the expected cgroups")
        self.assertFalse(os.path.exists(legacy_cpu_cgroup), "cleanup_legacy_cgroups() did not remove the CPU legacy cgroup")
        self.assertFalse(os.path.exists(legacy_memory_cgroup), "cleanup_legacy_cgroups() did not remove the memory legacy cgroup")
