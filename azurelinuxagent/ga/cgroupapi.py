# -*- coding: utf-8 -*-
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

import os
import re
import shutil
import subprocess
import threading
import uuid

from azurelinuxagent.common import logger
from azurelinuxagent.ga.cgroup import CpuCgroup, MemoryCgroup
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry, log_cgroup_info, log_cgroup_warning
from azurelinuxagent.common.conf import get_agent_pid_file_path
from azurelinuxagent.common.exception import CGroupsException, ExtensionErrorCodes, ExtensionError, \
    ExtensionOperationError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import systemd
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.ga.extensionprocessutil import handle_process_completion, read_output, \
    TELEMETRY_MESSAGE_MAX_LEN
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import get_distro

CGROUPS_FILE_SYSTEM_ROOT = '/sys/fs/cgroup'
EXTENSION_SLICE_PREFIX = "azure-vmextensions"


def get_cgroup_api():
    """
    Determines which version of Cgroups should be used for resource enforcement and monitoring by the Agent are returns
    the corresponding Api. If the required controllers are not mounted in v1 or v2, return None.
    """
    v1 = SystemdCgroupsApiv1()
    v2 = SystemdCgroupsApiv2()

    log_cgroup_info("Controllers mounted in v1: {0}. Controllers mounted in v2: {1}".format(v1.get_mounted_controllers(), v2.get_mounted_controllers()))

    # It is possible for different controllers to be simultaneously mounted under v1 and v2. If any are mounted under
    # v1, use v1.
    if v1.is_cpu_or_memory_mounted():
        log_cgroup_info("Using cgroups v1 for resource enforcement and monitoring")
        return v1
    elif v2.is_cpu_or_memory_mounted():
        log_cgroup_info("Using cgroups v2 for resource enforcement and monitoring")
        return v2
    else:
        log_cgroup_warning("CPU and Memory controllers are not mounted in cgroups v1 or v2")
        return None


class SystemdRunError(CGroupsException):
    """
    Raised when systemd-run fails
    """

    def __init__(self, msg=None):
        super(SystemdRunError, self).__init__(msg)


class CGroupsApi(object):
    @staticmethod
    def cgroups_supported():
        distro_info = get_distro()
        distro_name = distro_info[0]
        try:
            distro_version = FlexibleVersion(distro_info[1])
        except ValueError:
            return False
        return (distro_name.lower() == 'ubuntu' and distro_version.major >= 16) or \
               (distro_name.lower() in ('centos', 'redhat') and 8 <= distro_version.major < 9)

    @staticmethod
    def track_cgroups(extension_cgroups):
        try:
            for cgroup in extension_cgroups:
                CGroupsTelemetry.track_cgroup(cgroup)
        except Exception as exception:
            logger.warn("[CGW] Cannot add cgroup '{0}' to tracking list; resource usage will not be tracked. "
                        "Error: {1}".format(cgroup.path, ustr(exception)))

    @staticmethod
    def get_processes_in_cgroup(cgroup_path):
        with open(os.path.join(cgroup_path, "cgroup.procs"), "r") as cgroup_procs:
            return [int(pid) for pid in cgroup_procs.read().split()]

    @staticmethod
    def _foreach_legacy_cgroup(operation):
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent. Also,
        when running under systemd, the PIDs should not be explicitly moved to the cgroup filesystem. The older daemons would
        incorrectly do that under certain conditions.

        This method checks for the existence of the legacy cgroups and, if the daemon's PID has been added to them, executes the
        given operation on the cgroups. After this check, the method attempts to remove the legacy cgroups.

        :param operation:
            The function to execute on each legacy cgroup. It must take 2 arguments: the controller and the daemon's PID
        """
        legacy_cgroups = []
        for controller in ['cpu', 'memory']:
            cgroup = os.path.join(CGROUPS_FILE_SYSTEM_ROOT, controller, "WALinuxAgent", "WALinuxAgent")
            if os.path.exists(cgroup):
                log_cgroup_info('Found legacy cgroup {0}'.format(cgroup), send_event=False)
                legacy_cgroups.append((controller, cgroup))

        try:
            for controller, cgroup in legacy_cgroups:
                procs_file = os.path.join(cgroup, "cgroup.procs")

                if os.path.exists(procs_file):
                    procs_file_contents = fileutil.read_file(procs_file).strip()
                    daemon_pid = CGroupsApi.get_daemon_pid()

                    if ustr(daemon_pid) in procs_file_contents:
                        operation(controller, daemon_pid)
        finally:
            for _, cgroup in legacy_cgroups:
                log_cgroup_info('Removing {0}'.format(cgroup), send_event=False)
                shutil.rmtree(cgroup, ignore_errors=True)
        return len(legacy_cgroups)

    @staticmethod
    def get_daemon_pid():
        return int(fileutil.read_file(get_agent_pid_file_path()).strip())


class SystemdCgroupsApi(CGroupsApi):
    """
    Cgroups interface via systemd. Contains common api implementations between cgroups v1 and v2.
    """

    def __init__(self):
        self._cgroup_mountpoints = {}
        self._agent_unit_name = None
        self._systemd_run_commands = []
        self._systemd_run_commands_lock = threading.RLock()

    def get_systemd_run_commands(self):
        """
        Returns a list of the systemd-run commands currently running (given as PIDs)
        """
        with self._systemd_run_commands_lock:
            return self._systemd_run_commands[:]

    def is_cpu_or_memory_mounted(self):
        """
        Returns True if either cpu or memory controllers are mounted and enabled at the root cgroup.
        """
        cpu_mount_point, memory_mount_point = self.get_cgroup_mount_points()
        return cpu_mount_point is not None or memory_mount_point is not None

    def get_mounted_controllers(self):
        """
        Returns a list of the controllers mounted and enabled at the root cgroup. Currently, the only controllers the
        agent checks for is cpu and memory.
        """
        self.get_cgroup_mount_points()  # Updates self._cgroup_mountpoints if empty
        return [controller for controller, mount_point in self._cgroup_mountpoints.items() if mount_point is not None]

    def cleanup_legacy_cgroups(self):
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent. If
        we find that any of the legacy groups include the PID of the daemon then we need to disable data collection for this
        instance (under systemd, moving PIDs across the cgroup file system can produce unpredictable results)
        """
        return CGroupsApi._foreach_legacy_cgroup(lambda *_: None)

    @staticmethod
    def get_extension_slice_name(extension_name, old_slice=False):
        # The old slice makes it difficult for user to override the limits because they need to place drop-in files on every upgrade if extension slice is different for each version.
        # old slice includes <HandlerName>.<ExtensionName>-<HandlerVersion>
        # new slice without version <HandlerName>.<ExtensionName>
        if not old_slice:
            extension_name = extension_name.rsplit("-", 1)[0]
        # Since '-' is used as a separator in systemd unit names, we replace it with '_' to prevent side-effects.
        return EXTENSION_SLICE_PREFIX + "-" + extension_name.replace('-', '_') + ".slice"

    @staticmethod
    def _is_systemd_failure(scope_name, stderr):
        stderr.seek(0)
        stderr = ustr(stderr.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8', errors='backslashreplace')
        unit_not_found = "Unit {0} not found.".format(scope_name)
        return unit_not_found in stderr or scope_name not in stderr

    def get_cgroup_mount_points(self):
        """
        Cgroup version specific. Returns a tuple with the mount points for the cpu and memory controllers; the values
        can be None if the corresponding controller is not mounted or enabled at the root cgroup. Updates
        self._cgroup_mountpoints if empty.
        """
        return None, None

    def get_unit_cgroup_paths(self, unit_name):
        """
        Cgroup version specific. Returns a tuple with the path of the cpu and memory cgroups for the given unit.
        The values returned can be None if the controller is not mounted or enabled.
        """
        pass    # pylint: disable=W0107

    def get_process_cgroup_paths(self, process_id):
        """
        Cgroup version specific. Returns a tuple with the path of the cpu and memory cgroups for the given process.
        The 'process_id' can be a numeric PID or the string "self" for the current process.
        The values returned can be None if the process is not in a cgroup for that controller (e.g. the controller is
        not mounted or enabled).
        """
        pass    # pylint: disable=W0107

    def get_process_cgroup_relative_paths(self, process_id):  # pylint: disable=W0613
        """
        Cgroup version specific. Returns a tuple with the path of the cpu and memory cgroups for the given process
        (relative to the mount point of the corresponding controller).
        The 'process_id' can be a numeric PID or the string "self" for the current process.
        The values returned can be None if the process is not in a cgroup for that controller (e.g. the controller is
        not mounted).
        """
        pass    # pylint: disable=W0107

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        """
        Cgroup version specific. Starts extension command.
        """
        pass    # pylint: disable=W0107


class SystemdCgroupsApiv1(SystemdCgroupsApi):
    """
    Cgroups v1 interface via systemd
    """
    def get_cgroup_mount_points(self):
        # the output of mount is similar to
        #     $ findmnt -t cgroup --noheadings
        #     /sys/fs/cgroup/systemd          cgroup cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd
        #     /sys/fs/cgroup/memory           cgroup cgroup rw,nosuid,nodev,noexec,relatime,memory
        #     /sys/fs/cgroup/cpu,cpuacct      cgroup cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct
        #     etc
        #
        if not self._cgroup_mountpoints:
            cpu = None
            memory = None
            for line in shellutil.run_command(['findmnt', '-t', 'cgroup', '--noheadings']).splitlines():
                match = re.search(r'(?P<path>/\S+(memory|cpuacct))\s', line)
                if match is not None:
                    path = match.group('path')
                    if 'cpuacct' in path:
                        cpu = path
                    else:
                        memory = path
            self._cgroup_mountpoints = {'cpu': cpu, 'memory': memory}

        return self._cgroup_mountpoints['cpu'], self._cgroup_mountpoints['memory']

    def get_unit_cgroup_paths(self, unit_name):
        # Ex: ControlGroup=/azure.slice/walinuxagent.service
        #     controlgroup_path[1:] = azure.slice/walinuxagent.service
        controlgroup_path = systemd.get_unit_property(unit_name, "ControlGroup")
        cpu_mount_point, memory_mount_point = self.get_cgroup_mount_points()

        cpu_cgroup_path = os.path.join(cpu_mount_point, controlgroup_path[1:]) \
            if cpu_mount_point is not None else None

        memory_cgroup_path = os.path.join(memory_mount_point, controlgroup_path[1:]) \
            if memory_mount_point is not None else None

        return cpu_cgroup_path, memory_cgroup_path

    def get_process_cgroup_paths(self, process_id):
        cpu_cgroup_relative_path, memory_cgroup_relative_path = self.get_process_cgroup_relative_paths(process_id)

        cpu_mount_point, memory_mount_point = self.get_cgroup_mount_points()

        cpu_cgroup_path = os.path.join(cpu_mount_point, cpu_cgroup_relative_path) \
            if cpu_mount_point is not None and cpu_cgroup_relative_path is not None else None

        memory_cgroup_path = os.path.join(memory_mount_point, memory_cgroup_relative_path) \
            if memory_mount_point is not None and memory_cgroup_relative_path is not None else None

        return cpu_cgroup_path, memory_cgroup_path

    def get_process_cgroup_relative_paths(self, process_id):
        # The contents of the file are similar to
        #    # cat /proc/1218/cgroup
        #    10:memory:/system.slice/walinuxagent.service
        #    3:cpu,cpuacct:/system.slice/walinuxagent.service
        #    etc
        cpu_path = None
        memory_path = None
        for line in fileutil.read_file("/proc/{0}/cgroup".format(process_id)).splitlines():
            match = re.match(r'\d+:(?P<controller>(memory|.*cpuacct.*)):(?P<path>.+)', line)
            if match is not None:
                controller = match.group('controller')
                path = match.group('path').lstrip('/') if match.group('path') != '/' else None
                if controller == 'memory':
                    memory_path = path
                else:
                    cpu_path = path

        return cpu_path, memory_path

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        scope = "{0}_{1}".format(cmd_name, uuid.uuid4())
        extension_slice_name = self.get_extension_slice_name(extension_name)
        with self._systemd_run_commands_lock:
            process = subprocess.Popen(  # pylint: disable=W1509
                # Some distros like ubuntu20 by default cpu and memory accounting enabled. Thus create nested cgroups under the extension slice
                # So disabling CPU and Memory accounting prevents from creating nested cgroups, so that all the counters will be present in extension Cgroup
                # since slice unit file configured with accounting enabled.
                "systemd-run --property=CPUAccounting=no --property=MemoryAccounting=no --unit={0} --scope --slice={1} {2}".format(
                    scope, extension_slice_name, command),
                shell=shell,
                cwd=cwd,
                stdout=stdout,
                stderr=stderr,
                env=env,
                preexec_fn=os.setsid)

            # We start systemd-run with shell == True so process.pid is the shell's pid, not the pid for systemd-run
            self._systemd_run_commands.append(process.pid)

        scope_name = scope + '.scope'

        log_cgroup_info("Started extension in unit '{0}'".format(scope_name), send_event=False)

        cpu_cgroup = None
        try:
            cgroup_relative_path = os.path.join('azure.slice/azure-vmextensions.slice', extension_slice_name)

            cpu_cgroup_mountpoint, memory_cgroup_mountpoint = self.get_cgroup_mount_points()

            if cpu_cgroup_mountpoint is None:
                log_cgroup_info("The CPU controller is not mounted; will not track resource usage", send_event=False)
            else:
                cpu_cgroup_path = os.path.join(cpu_cgroup_mountpoint, cgroup_relative_path)
                cpu_cgroup = CpuCgroup(extension_name, cpu_cgroup_path)
                CGroupsTelemetry.track_cgroup(cpu_cgroup)

            if memory_cgroup_mountpoint is None:
                log_cgroup_info("The Memory controller is not mounted; will not track resource usage", send_event=False)
            else:
                memory_cgroup_path = os.path.join(memory_cgroup_mountpoint, cgroup_relative_path)
                memory_cgroup = MemoryCgroup(extension_name, memory_cgroup_path)
                CGroupsTelemetry.track_cgroup(memory_cgroup)

        except IOError as e:
            if e.errno == 2:  # 'No such file or directory'
                log_cgroup_info("The extension command already completed; will not track resource usage",
                                send_event=False)
            log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(e)),
                            send_event=False)
        except Exception as e:
            log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(e)), send_event=False)

        # Wait for process completion or timeout
        try:
            return handle_process_completion(process=process, command=command, timeout=timeout, stdout=stdout,
                                             stderr=stderr, error_code=error_code, cpu_cgroup=cpu_cgroup)
        except ExtensionError as e:
            # The extension didn't terminate successfully. Determine whether it was due to systemd errors or
            # extension errors.
            if not self._is_systemd_failure(scope, stderr):
                # There was an extension error; it either timed out or returned a non-zero exit code. Re-raise the error
                raise

            # There was an issue with systemd-run. We need to log it and retry the extension without systemd.
            process_output = read_output(stdout, stderr)
            # Reset the stdout and stderr
            stdout.truncate(0)
            stderr.truncate(0)

            if isinstance(e, ExtensionOperationError):
                # no-member: Instance of 'ExtensionError' has no 'exit_code' member (no-member) - Disabled: e is actually an ExtensionOperationError
                err_msg = 'Systemd process exited with code %s and output %s' % (
                    e.exit_code, process_output)  # pylint: disable=no-member
            else:
                err_msg = "Systemd timed-out, output: %s" % process_output
            raise SystemdRunError(err_msg)
        finally:
            with self._systemd_run_commands_lock:
                self._systemd_run_commands.remove(process.pid)


class SystemdCgroupsApiv2(SystemdCgroupsApi):
    """
    Cgroups v2 interface via systemd
    """

    def is_controller_enabled(self, controller, cgroup_path):
        """
        Returns True if the provided controller is enabled at the provided cgroup.

        There are two ways to determine if a controller is enabled at the provided cgroup:

        1. For non-leaf cgroups, the cgroup.subtree_control shows space separated list of the controllers which are
        enabled to control resource distribution from the cgroup to its children. All non-root "cgroup.subtree_control"
        files can only contain controllers which are enabled in the parent's "cgroup.subtree_control" file.
                $ cat /sys/fs/cgroup/cgroup.subtree_control
                cpuset cpu io memory hugetlb pids rdma misc

        2. For leaf cgroups, the cgroup.subtree_control file will be empty and the presence of "<controller>."
        prefixed interface files at the path indicate the controller is enabled.
                $ ls /sys/fs/cgroup/azure.slice/walinuxagent.service/
                cgroup.controllers  cgroup.max.descendants  cgroup.threads  cpu.pressure    cpu.weight.nice      memory.high       memory.oom.group  memory.swap.current  memory.zswap.current  pids.peak
                cgroup.events       cgroup.pressure         cgroup.type     cpu.stat        io.pressure          memory.low        memory.peak       memory.swap.events   memory.zswap.max
                cgroup.freeze       cgroup.procs            cpu.idle        cpu.uclamp.max  memory.current       memory.max        memory.pressure   memory.swap.high     pids.current
                cgroup.kill         cgroup.stat             cpu.max         cpu.uclamp.min  memory.events        memory.min        memory.reclaim    memory.swap.max      pids.events
                cgroup.max.depth    cgroup.subtree_control  cpu.max.burst   cpu.weight      memory.events.local  memory.numa_stat  memory.stat       memory.swap.peak     pids.max

        If either check is True, the controller is enabled at the cgroup. Check 1 is necessary because no controller
        interface files exist at the root cgroup, even if the controller is enabled.
        """
        if cgroup_path is not None and controller is not None:
            # Check that the controller is enabled in the cgroup.subtree_control file
            enabled_controllers_file = os.path.join(cgroup_path, 'cgroup.subtree_control')
            if os.path.exists(enabled_controllers_file):
                enabled_controllers = fileutil.read_file(enabled_controllers_file).rstrip().split(" ")
                if controller in enabled_controllers:
                    return True

            # Check that the controller interface files exist in the cgroup
            if os.path.exists(cgroup_path):
                for item in os.listdir(cgroup_path):
                    if item.startswith(controller + '.'):
                        return True

        return False

    def get_cgroup_mount_points(self):
        # The output of mount is similar to
        #     $ findmnt -t cgroup2 --noheadings
        #     /sys/fs/cgroup cgroup2 cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot
        #
        # Since v2 is a unified hierarchy, this method checks if each controller is enabled at the root cgroup. This
        # check is necessary because all non-root "cgroup.subtree_control" files can only contain controllers which are
        # enabled in the parent's "cgroup.subtree_control" file.

        if not self._cgroup_mountpoints:
            cpu = None
            memory = None
            for line in shellutil.run_command(['findmnt', '-t', 'cgroup2', '--noheadings']).splitlines():
                match = re.search(r'(?P<path>/\S+)\s+cgroup2', line)
                if match is not None:
                    mount_point = match.group('path')
                    if self.is_controller_enabled('cpu', mount_point):
                        cpu = mount_point
                    if self.is_controller_enabled('memory', mount_point):
                        memory = mount_point
            self._cgroup_mountpoints = {'cpu': cpu, 'memory': memory}

        return self._cgroup_mountpoints['cpu'], self._cgroup_mountpoints['memory']

    def get_unit_cgroup_paths(self, unit_name):
        # Ex: ControlGroup=/azure.slice/walinuxagent.service
        #     controlgroup_path[1:] = azure.slice/walinuxagent.service
        controlgroup_path = systemd.get_unit_property(unit_name, "ControlGroup")
        cpu_mount_point, memory_mount_point = self.get_cgroup_mount_points()

        # Since v2 is a unified hierarchy, we need to check if each controller is enabled for the cgroup. If a
        # controller is not enabled, then its controller interface files won't exist at the cgroup path
        cpu_cgroup_path = None
        if cpu_mount_point is not None:
            cgroup_path = os.path.join(cpu_mount_point, controlgroup_path[1:])
            if self.is_controller_enabled('cpu', cgroup_path):
                cpu_cgroup_path = cgroup_path

        memory_cgroup_path = None
        if memory_mount_point is not None:
            cgroup_path = os.path.join(memory_mount_point, controlgroup_path[1:])
            if self.is_controller_enabled('memory', cgroup_path):
                memory_cgroup_path = cgroup_path

        return cpu_cgroup_path, memory_cgroup_path

    def get_process_cgroup_paths(self, process_id):
        cpu_cgroup_relative_path, memory_cgroup_relative_path = self.get_process_cgroup_relative_paths(process_id)
        cpu_mount_point, memory_mount_point = self.get_cgroup_mount_points()

        # Since v2 is a unified hierarchy, we need to check if each controller is enabled for the cgroup. If a
        # controller is not enabled, then its controller interface files won't exist at the cgroup path
        cpu_cgroup_path = None
        if cpu_mount_point is not None and cpu_cgroup_relative_path is not None:
            cgroup_path = os.path.join(cpu_mount_point, cpu_cgroup_relative_path)
            if self.is_controller_enabled('cpu', cgroup_path):
                cpu_cgroup_path = cgroup_path

        memory_cgroup_path = None
        if memory_mount_point is not None and memory_cgroup_relative_path is not None:
            cgroup_path = os.path.join(memory_mount_point, memory_cgroup_relative_path)
            if self.is_controller_enabled('memory', cgroup_path):
                memory_cgroup_path = cgroup_path

        return cpu_cgroup_path, memory_cgroup_path

    def get_process_cgroup_relative_paths(self, process_id):
        # The contents of the file are similar to
        #    # cat /proc/1218/cgroup
        #    0::/azure.slice/walinuxagent.service
        cpu_path = None
        memory_path = None
        for line in fileutil.read_file("/proc/{0}/cgroup".format(process_id)).splitlines():
            match = re.match(r'\d+::(?P<path>\S+)', line)
            if match is not None:
                path = match.group('path').lstrip('/') if match.group('path') != '/' else None
                memory_path = path
                cpu_path = path

        return cpu_path, memory_path

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr, error_code=ExtensionErrorCodes.PluginUnknownFailure):   # pylint: disable=W0613
        """
        Currently, the agent will not enable cgroups v2 or use SystemdCgroupv2Api() to start extension commands. Raising
         an exception here for CGroupConfigurator to catch in case v2 is improperly enabled.
        """
        error_msg = "The agent does not currently support running extensions in cgroups v2"
        log_cgroup_warning(error_msg)
        raise CGroupsException(msg=error_msg)

