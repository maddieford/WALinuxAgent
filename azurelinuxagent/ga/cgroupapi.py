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
import json
import os
import re
import shutil
import subprocess
import threading
import uuid

from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.ga.controllermetrics import CpuMetrics, MemoryMetrics
from azurelinuxagent.ga.cgroupstelemetry import CGroupsTelemetry
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

CGROUP_FILE_SYSTEM_ROOT = '/sys/fs/cgroup'
EXTENSION_SLICE_PREFIX = "azure-vmextensions"


def log_cgroup_info(formatted_string, op=WALAEventOperation.CGroupsInfo, send_event=True):
    logger.info("[CGI] " + formatted_string)
    if send_event:
        add_event(op=op, message=formatted_string)


def log_cgroup_warning(formatted_string, op=WALAEventOperation.CGroupsInfo, send_event=True):
    logger.info("[CGW] " + formatted_string)  # log as INFO for now, in the future it should be logged as WARNING
    if send_event:
        add_event(op=op, message=formatted_string, is_success=False, log_event=False)


class CGroupUtil(object):
    """
    Cgroup utility methods which are independent of systemd cgroup api.
    """
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
    def get_extension_slice_name(extension_name, old_slice=False):
        # The old slice makes it difficult for user to override the limits because they need to place drop-in files on every upgrade if extension slice is different for each version.
        # old slice includes <HandlerName>.<ExtensionName>-<HandlerVersion>
        # new slice without version <HandlerName>.<ExtensionName>
        if not old_slice:
            extension_name = extension_name.rsplit("-", 1)[0]
        # Since '-' is used as a separator in systemd unit names, we replace it with '_' to prevent side-effects.
        return EXTENSION_SLICE_PREFIX + "-" + extension_name.replace('-', '_') + ".slice"

    @staticmethod
    def get_daemon_pid():
        return int(fileutil.read_file(get_agent_pid_file_path()).strip())

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
            cgroup = os.path.join(CGROUP_FILE_SYSTEM_ROOT, controller, "WALinuxAgent", "WALinuxAgent")
            if os.path.exists(cgroup):
                log_cgroup_info('Found legacy cgroup {0}'.format(cgroup), send_event=False)
                legacy_cgroups.append((controller, cgroup))

        try:
            for controller, cgroup in legacy_cgroups:
                procs_file = os.path.join(cgroup, "cgroup.procs")

                if os.path.exists(procs_file):
                    procs_file_contents = fileutil.read_file(procs_file).strip()
                    daemon_pid = CGroupUtil.get_daemon_pid()

                    if ustr(daemon_pid) in procs_file_contents:
                        operation(controller, daemon_pid)
        finally:
            for _, cgroup in legacy_cgroups:
                log_cgroup_info('Removing {0}'.format(cgroup), send_event=False)
                shutil.rmtree(cgroup, ignore_errors=True)
        return len(legacy_cgroups)

    @staticmethod
    def cleanup_legacy_cgroups():
        """
        Previous versions of the daemon (2.2.31-2.2.40) wrote their PID to /sys/fs/cgroup/{cpu,memory}/WALinuxAgent/WALinuxAgent;
        starting from version 2.2.41 we track the agent service in walinuxagent.service instead of WALinuxAgent/WALinuxAgent. If
        we find that any of the legacy groups include the PID of the daemon then we need to disable data collection for this
        instance (under systemd, moving PIDs across the cgroup file system can produce unpredictable results)
        """
        return CGroupUtil._foreach_legacy_cgroup(lambda *_: None)


class SystemdRunError(CGroupsException):
    """
    Raised when systemd-run fails
    """

    def __init__(self, msg=None):
        super(SystemdRunError, self).__init__(msg)


class InvalidCgroupMountpointException(CGroupsException):
    """
    Raised when the cgroup mountpoint is invalid.
    """

    def __init__(self, msg=None):
        super(InvalidCgroupMountpointException, self).__init__(msg)


def get_cgroup_api():
    """
    Determines which version of Cgroup should be used for resource enforcement and monitoring by the Agent and returns
    the corresponding Api.

    Uses 'stat -f --format=%T /sys/fs/cgroup' to get the cgroup hierarchy in use.
        If the result is 'cgroup2fs', cgroup v2 is being used.
        If the result is 'tmpfs', cgroup v1 or a hybrid mode is being used.
            If the result of 'stat -f --format=%T /sys/fs/cgroup/unified' is 'cgroup2fs', then hybrid mode is being used.

    Raises exception if cgroup filesystem mountpoint is not '/sys/fs/cgroup', or an unknown mode is detected. Also
    raises exception if hybrid mode is detected and there are controllers available to be enabled in the unified
    hierarchy (the agent does not support cgroups if there are controllers simultaneously attached to v1 and v2
    hierarchies).
    """
    if not os.path.exists(CGROUP_FILE_SYSTEM_ROOT):
        v1_mount_point = shellutil.run_command(['findmnt', '-t', 'cgroup', '--noheadings'])
        v2_mount_point = shellutil.run_command(['findmnt', '-t', 'cgroup2', '--noheadings'])
        raise InvalidCgroupMountpointException("Expected cgroup filesystem to be mounted at '{0}', but it is not.\n v1 mount point: \n{1}\n v2 mount point: \n{2}".format(CGROUP_FILE_SYSTEM_ROOT, v1_mount_point, v2_mount_point))

    root_hierarchy_mode = shellutil.run_command(["stat", "-f", "--format=%T", CGROUP_FILE_SYSTEM_ROOT]).rstrip()

    if root_hierarchy_mode == "cgroup2fs":
        log_cgroup_info("Using cgroup v2 for resource enforcement and monitoring")
        return SystemdCgroupApiv2()

    elif root_hierarchy_mode == "tmpfs":
        # Check if a hybrid mode is being used
        unified_hierarchy_path = os.path.join(CGROUP_FILE_SYSTEM_ROOT, "unified")
        if os.path.exists(unified_hierarchy_path) and shellutil.run_command(["stat", "-f", "--format=%T", unified_hierarchy_path]).rstrip() == "cgroup2fs":
            # Hybrid mode is being used. Check if any controllers are available to be enabled in the unified hierarchy.
            available_unified_controllers_file = os.path.join(unified_hierarchy_path, "cgroup.controllers")
            if os.path.exists(available_unified_controllers_file):
                available_unified_controllers = fileutil.read_file(available_unified_controllers_file).rstrip()
                if available_unified_controllers != "":
                    raise CGroupsException("Detected hybrid cgroup mode, but there are controllers available to be enabled in unified hierarchy: {0}".format(available_unified_controllers))

        cgroup_api_v1 = SystemdCgroupApiv1()
        # Previously the agent supported users mounting cgroup v1 controllers in locations other than the systemd
        # default ('/sys/fs/cgroup'). The agent no longer supports this scenario. If any agent supported controller is
        # mounted in a location other than the systemd default, raise Exception.
        if not cgroup_api_v1.are_mountpoints_systemd_created():
            raise InvalidCgroupMountpointException("Expected cgroup controllers to be mounted at '{0}', but at least one is not. v1 mount points: \n{1}".format(CGROUP_FILE_SYSTEM_ROOT, json.dumps(cgroup_api_v1.get_controller_mount_points())))
        log_cgroup_info("Using cgroup v1 for resource enforcement and monitoring")
        return cgroup_api_v1

    raise CGroupsException("{0} has an unexpected file type: {1}".format(CGROUP_FILE_SYSTEM_ROOT, root_hierarchy_mode))


class _SystemdCgroupApi(object):
    """
    Cgroup interface via systemd. Contains common api implementations between cgroup v1 and v2.
    """
    def __init__(self):
        self._systemd_run_commands = []
        self._systemd_run_commands_lock = threading.RLock()

    def get_systemd_run_commands(self):
        """
        Returns a list of the systemd-run commands currently running (given as PIDs)
        """
        with self._systemd_run_commands_lock:
            return self._systemd_run_commands[:]
    #
    # def get_controller_mount_points(self):
    #     """
    #     Cgroup version specific. Returns a tuple with the root paths for the cpu and memory controllers; the values can
    #     be None if the corresponding controller is not mounted or enabled at the root cgroup.
    #     """
    #     raise NotImplementedError()

    # def get_unit_cgroup_paths(self, unit_name):
    #     """
    #     Returns a tuple with the path of the cpu and memory cgroups for the given unit.
    #     The values returned can be None if the controller is not mounted or enabled.
    #     """
    #     # Ex: ControlGroup=/azure.slice/walinuxagent.service
    #     #     controlgroup_path[1:] = azure.slice/walinuxagent.service
    #     controlgroup_path = systemd.get_unit_property(unit_name, "ControlGroup")
    #     cpu_root_path, memory_root_path = self.get_controller_mount_points()
    #
    #     cpu_cgroup_path = os.path.join(cpu_root_path, controlgroup_path[1:]) \
    #         if cpu_root_path is not None else None
    #
    #     memory_cgroup_path = os.path.join(memory_root_path, controlgroup_path[1:]) \
    #         if memory_root_path is not None else None
    #
    #     return cpu_cgroup_path, memory_cgroup_path

    def get_unit_cgroup(self, unit_name, cgroup_name):
        """
        Cgroup version specific. Returns a representation of the unit cgroup.
        """
        raise NotImplementedError()

    # def get_process_cgroup_paths(self, process_id):
    #     """
    #     Returns a tuple with the path of the cpu and memory cgroups for the given process.
    #     The 'process_id' can be a numeric PID or the string "self" for the current process.
    #     The values returned can be None if the controller is not mounted or enabled.
    #     """
    #     cpu_cgroup_relative_path, memory_cgroup_relative_path = self.get_process_cgroup_relative_controller_mount_points(process_id)
    #
    #     cpu_root_path, memory_root_path = self.get_controller_mount_points()
    #
    #     cpu_cgroup_path = os.path.join(cpu_root_path, cpu_cgroup_relative_path) \
    #         if cpu_root_path is not None and cpu_cgroup_relative_path is not None else None
    #
    #     memory_cgroup_path = os.path.join(memory_root_path, memory_cgroup_relative_path) \
    #         if memory_root_path is not None and memory_cgroup_relative_path is not None else None
    #
    #     return cpu_cgroup_path, memory_cgroup_path

    def get_cgroup_from_relative_path(self, cgroup_name, relative_path):
        """
        Cgroup version specific. Returns a representation of the cgroup at the provided relative path.
        """
        raise NotImplementedError()

    def get_process_cgroup(self, process_id, cgroup_name):
        """
        Cgroup version specific. Returns a representation of a process' cgroup.
        """
        raise NotImplementedError()

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        """
        Cgroup version specific. Starts extension command.
        """
        raise NotImplementedError()

    def log_root_paths(self):
        """
        Cgroup version specific. Logs the root paths of the controllers.
        """
        raise NotImplementedError()

    @staticmethod
    def _is_systemd_failure(scope_name, stderr):
        stderr.seek(0)
        stderr = ustr(stderr.read(TELEMETRY_MESSAGE_MAX_LEN), encoding='utf-8', errors='backslashreplace')
        unit_not_found = "Unit {0} not found.".format(scope_name)
        return unit_not_found in stderr or scope_name not in stderr

    @staticmethod
    def get_processes_in_cgroup(cgroup):
        """
        Returns a list of all the process ids in the provided cgroup (azurelinuxagent.ga.cgroup.Cgroup).
        """
        cgroup_paths = cgroup.get_cgroup_paths()
        pids = set()
        for cgroup_path in cgroup_paths:
            with open(os.path.join(cgroup_path, "cgroup.procs"), "r") as cgroup_procs:
                for pid in cgroup_procs.read().split():
                    pids.add(int(pid))
        return pids


class SystemdCgroupApiv1(_SystemdCgroupApi):
    """
    Cgroup v1 interface via systemd
    """
    def __init__(self):
        super(SystemdCgroupApiv1, self).__init__()
        self._cgroup_mountpoints = self._get_controller_mountpoints()

    def _get_controller_mountpoints(self):
        """
        In v1, each controller is mounted at a different path. Use findmnt to get each path.

            the output of findmnt is similar to
                $ findmnt -t cgroup --noheadings
                /sys/fs/cgroup/systemd          cgroup cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd
                /sys/fs/cgroup/memory           cgroup cgroup rw,nosuid,nodev,noexec,relatime,memory
                /sys/fs/cgroup/cpu,cpuacct      cgroup cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct
                etc

        Returns a dictionary of the controller-path mappings. The dictionary only includes the controllers which are
        supported by the agent.
        """
        mount_points = {}
        for line in shellutil.run_command(['findmnt', '-t', 'cgroup', '--noheadings']).splitlines():
            # In v2, we match only the systemd default mountpoint ('/sys/fs/cgroup'). In v1, we match any path. This
            # is because the agent previously supported users mounting controllers at locations other than the systemd
            # default in v1.
            match = re.search(r'(?P<path>\S+\/(?P<controller>\S+))\s+cgroup', line)
            if match is not None:
                path = match.group('path')
                controller = match.group('controller')
                if controller is not None and path is not None and controller in CgroupV1.get_supported_controllers():
                    mount_points[controller] = path
        return mount_points

    def are_mountpoints_systemd_created(self):
        """
        Systemd mounts each controller at '/sys/fs/cgroup/<controller>'. Returns True if all controllers supported by
        the agent have mountpoints which match this pattern, False otherwise.

        The agent does not support cgroup usage if the default root systemd mountpoint (/sys/fs/cgroup) is not used.
        This method is used to check if any users are using non-systemd mountpoints. If they are, the agent drop-in
        files will be cleaned up in cgroupconfigurator.
        """
        for controller, mount_point in self._cgroup_mountpoints.items():
            if mount_point != os.path.join(CGROUP_FILE_SYSTEM_ROOT, controller):
                return False

        return True
        # cpu_mountpoint = self._cgroup_mountpoints.get(CgroupV1.CPU_CONTROLLER)
        # memory_mountpoint = self._cgroup_mountpoints.get(CgroupV1.MEMORY_CONTROLLER)
        # if cpu_mountpoint is not None and cpu_mountpoint != os.path.join(CGROUP_FILE_SYSTEM_ROOT, CgroupV1.CPU_CONTROLLER):
        #     return False
        # if memory_mountpoint is not None and memory_mountpoint != os.path.join(CGROUP_FILE_SYSTEM_ROOT, CgroupV1.MEMORY_CONTROLLER):
        #     return False
        # return True

    def get_controller_mount_points(self):
        """
        Returns a dictionary of controller-mount_point mappings
        """
        return self._cgroup_mountpoints

    def get_process_cgroup_relative_controller_mount_points(self, process_id):
        # # The contents of the file are similar to
        # #    # cat /proc/1218/cgroup
        # #    10:memory:/system.slice/walinuxagent.service
        # #    3:cpu,cpuacct:/system.slice/walinuxagent.service
        # #    etc
        # cpu_path = None
        # memory_path = None
        # for line in fileutil.read_file("/proc/{0}/cgroup".format(process_id)).splitlines():
        #     match = re.match(r'\d+:(?P<controller>(memory|.*cpuacct.*)):(?P<path>.+)', line)
        #     if match is not None:
        #         controller = match.group('controller')
        #         path = match.group('path').lstrip('/') if match.group('path') != '/' else None
        #         if controller == 'memory':
        #             memory_path = path
        #         else:
        #             cpu_path = path
        #
        # return cpu_path, memory_path

        # The contents of the file are similar to
        #    # cat /proc/1218/cgroup
        #    10:memory:/system.slice/walinuxagent.service
        #    3:cpu,cpuacct:/system.slice/walinuxagent.service
        #    etc
        """
        The contents of the /proc/{process_id}/cgroup file are similar to
            # cat /proc/1218/cgroup
            10:memory:/system.slice/walinuxagent.service
            3:cpu,cpuacct:/system.slice/walinuxagent.service
            etc

        Returns the relative paths of the cgroup for the given process as a dict of controller-path mappings.
        The 'process_id' can be a numeric PID or the string "self" for the current process.
        """
        conroller_relative_paths = {}
        for line in fileutil.read_file("/proc/{0}/cgroup".format(process_id)).splitlines():
            match = re.match(r'\d+:(?P<controller>.+):(?P<path>.+)', line)
            if match is not None:
                controller = match.group('controller')
                path = match.group('path').lstrip('/') if match.group('path') != '/' else None
                if path is not None and controller in CgroupV1.get_supported_controllers():
                    conroller_relative_paths[controller] = path

        return conroller_relative_paths

    def get_unit_cgroup(self, unit_name, cgroup_name):
        unit_controlgroup_path = systemd.get_unit_property(unit_name, "ControlGroup")

        unit_cgroup_paths = {}
        for controller, mount_point in self._cgroup_mountpoints.items():
            unit_cgroup_paths[controller] = os.path.join(mount_point, unit_controlgroup_path[1:])

        return CgroupV1(cgroup_name=cgroup_name, mount_points=self._cgroup_mountpoints, cgroup_paths=unit_cgroup_paths)

    def get_cgroup_from_relative_path(self, cgroup_name, relative_path):
        cgroup_paths = {}
        for controller, mount_point in self._cgroup_mountpoints.items():
            cgroup_paths[controller] = os.path.join(mount_point, relative_path)

        return CgroupV1(cgroup_name=cgroup_name, mount_points=self._cgroup_mountpoints, cgroup_paths=cgroup_paths)

    def get_process_cgroup(self, process_id, cgroup_name):
        controller_relative_mount_points = self.get_process_cgroup_relative_controller_mount_points(process_id)

        process_cgroup_mount_points = {}
        for controller, mount_point in self._cgroup_mountpoints.items():
            controller_relative_path = controller_relative_mount_points.get(controller)
            if controller_relative_path is not None:
                process_cgroup_mount_points[controller] = os.path.join(mount_point, controller_relative_path)

        return CgroupV1(cgroup_name=cgroup_name, mount_points=self._cgroup_mountpoints,
                        cgroup_paths=process_cgroup_mount_points)

    def log_root_paths(self):
        for controller in CgroupV1.get_supported_controllers():
            mount_point = self._cgroup_mountpoints.get(controller)
            if mount_point is None:
                log_cgroup_info("The {0} controller is not mounted".format(controller), send_event=False)
            else:
                log_cgroup_info("The {0} controller is mounted at {1}".format(controller, mount_point), send_event=False)

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        scope = "{0}_{1}".format(cmd_name, uuid.uuid4())
        extension_slice_name = CGroupUtil.get_extension_slice_name(extension_name)
        with self._systemd_run_commands_lock:
            process = subprocess.Popen(  # pylint: disable=W1509
                # Some distros like ubuntu20 by default cpu and memory accounting enabled. Thus create nested cgroups under the extension slice
                # So disabling CPU and Memory accounting prevents from creating nested cgroups, so that all the counters will be present in extension Cgroup
                # since slice unit file configured with accounting enabled.
                "systemd-run --property=CPUAccounting=no --property=MemoryAccounting=no --unit={0} --scope --slice={1} {2}".format(scope, extension_slice_name, command),
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

        cpu_metrics = None
        try:
            cgroup_relative_path = os.path.join('azure.slice/azure-vmextensions.slice', extension_slice_name)
            cgroup = self.get_cgroup_from_relative_path(extension_name, cgroup_relative_path)
            cgroup.check_all_supported_controllers_enabled()
            metrics = cgroup.get_controller_metrics()
            for metric in metrics:
                if isinstance(metric, CpuMetrics):
                    cpu_metrics = metric
                CGroupsTelemetry.track_cgroup(metric)

            # cpu_cgroup_mountpoint, memory_cgroup_mountpoint = self.get_controller_mount_points()
            #
            # if cpu_cgroup_mountpoint is None:
            #     log_cgroup_info("The CPU controller is not mounted; will not track resource usage", send_event=False)
            # else:
            #     cpu_cgroup_path = os.path.join(cpu_cgroup_mountpoint, cgroup_relative_path)
            #     cpu_cgroup = CpuMetrics(extension_name, cpu_cgroup_path)
            #     CGroupsTelemetry.track_cgroup(cpu_cgroup)
            #
            # if memory_cgroup_mountpoint is None:
            #     log_cgroup_info("The Memory controller is not mounted; will not track resource usage", send_event=False)
            # else:
            #     memory_cgroup_path = os.path.join(memory_cgroup_mountpoint, cgroup_relative_path)
            #     memory_cgroup = MemoryMetrics(extension_name, memory_cgroup_path)
            #     CGroupsTelemetry.track_cgroup(memory_cgroup)

        except IOError as e:
            if e.errno == 2:  # 'No such file or directory'
                log_cgroup_info("The extension command already completed; will not track resource usage", send_event=False)
            log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(e)), send_event=False)
        except Exception as e:
            log_cgroup_info("Failed to start tracking resource usage for the extension: {0}".format(ustr(e)), send_event=False)

        # Wait for process completion or timeout
        try:
            return handle_process_completion(process=process, command=command, timeout=timeout, stdout=stdout,
                                             stderr=stderr, error_code=error_code, cpu_metrics=cpu_metrics)
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


class SystemdCgroupApiv2(_SystemdCgroupApi):
    """
    Cgroup v2 interface via systemd
    """
    def __init__(self):
        super(SystemdCgroupApiv2, self).__init__()
        self._root_cgroup_path = self._get_root_cgroup_path()
        self._controllers_enabled_at_root = self._get_controllers_enabled_at_root(self._root_cgroup_path) if self._root_cgroup_path != "" else []

    @staticmethod
    def _get_root_cgroup_path():
        """
        In v2, there is a unified mount point shared by all controllers. Use findmnt to get the unified mount point.

          The output of findmnt is similar to
              $ findmnt -t cgroup2 --noheadings
              /sys/fs/cgroup cgroup2 cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot

        Returns empty string if the root cgroup cannot be determined from the output above.
        """
        #
        for line in shellutil.run_command(['findmnt', '-t', 'cgroup2', '--noheadings']).splitlines():
            # Systemd mounts the cgroup filesystem at '/sys/fs/cgroup'. The agent does not support cgroups if the
            # filesystem is mounted elsewhere, so search specifically for '/sys/fs/cgroup' in the findmnt output.
            match = re.search(r'(?P<path>\/sys\/fs\/cgroup)\s+cgroup2', line)
            if match is not None:
                root_cgroup_path = match.group('path')
                if root_cgroup_path is not None:
                    return root_cgroup_path
        return ""

    @staticmethod
    def _get_controllers_enabled_at_root(root_cgroup_path):
        """
        Returns a list of the controllers enabled at the root cgroup. The cgroup.subtree_control file at the root shows
        a space separated list of the controllers which are enabled to control resource distribution from the root
        cgroup to its children. If a controller is listed here, then that controller is available to enable in children
        cgroups. This method filters the list to only inlcude controllers which are supported by the agent.

                $ cat /sys/fs/cgroup/cgroup.subtree_control
                cpuset cpu io memory hugetlb pids rdma misc
        """
        enabled_controllers_file = os.path.join(root_cgroup_path, 'cgroup.subtree_control')
        if os.path.exists(enabled_controllers_file):
            controllers_enabled_at_root = fileutil.read_file(enabled_controllers_file).rstrip().split()
            return list(set(controllers_enabled_at_root) & set(CgroupV2.get_supported_controllers()))
        return []

    def get_process_cgroup_relative_path(self, process_id):
        """
        The contents of the /proc/{process_id}/cgroup file are similar to
            # cat /proc/1218/cgroup
            0::/azure.slice/walinuxagent.service

        Returns the relative paths of the cgroup for the given process.
        The 'process_id' can be a numeric PID or the string "self" for the current process.
        """
        # The contents of the file are similar to
        #    # cat /proc/1218/cgroup
        #    0::/azure.slice/walinuxagent.service
        relative_path = ""
        for line in fileutil.read_file("/proc/{0}/cgroup".format(process_id)).splitlines():
            match = re.match(r'0::(?P<path>\S+)', line)
            if match is not None:
                relative_path = match.group('path').lstrip('/') if match.group('path') != '/' else ""

        return relative_path

    def get_unit_cgroup(self, unit_name, cgroup_name):
        unit_controlgroup_path = systemd.get_unit_property(unit_name, "ControlGroup")

        unified_unit_path = ""
        if self._root_cgroup_path != "":
            unified_unit_path = os.path.join(self._root_cgroup_path, unit_controlgroup_path[1:])

        return CgroupV2(cgroup_name=cgroup_name, root_cgroup_path=self._root_cgroup_path, cgroup_path=unified_unit_path,
                        enabled_controllers=self._controllers_enabled_at_root)

    def get_cgroup_from_relative_path(self, cgroup_name, relative_path):
        unified_cgroup_path = ""
        if self._root_cgroup_path != "":
            unified_cgroup_path = os.path.join(self._root_cgroup_path, relative_path)

        return CgroupV2(cgroup_name=cgroup_name, root_cgroup_path=self._root_cgroup_path,
                        cgroup_path=unified_cgroup_path, enabled_controllers=self._controllers_enabled_at_root)

    def get_process_cgroup(self, process_id, cgroup_name):
        process_relative_path = self.get_process_cgroup_relative_path(process_id)

        unified_unit_path = ""
        if self._root_cgroup_path != "" and process_relative_path != "":
            unified_unit_path = os.path.join(self._root_cgroup_path, process_relative_path)

        return CgroupV2(cgroup_name=cgroup_name, root_cgroup_path=self._root_cgroup_path, cgroup_path=unified_unit_path,
                        enabled_controllers=self._controllers_enabled_at_root)

    def log_root_paths(self):
        log_cgroup_info("The root cgroup path is {0}".format(self._root_cgroup_path), send_event=False)
        for controller in CgroupV2.get_supported_controllers():
            if controller in self._controllers_enabled_at_root:
                log_cgroup_info("The {0} controller is enabled at the root cgroup".format(controller), send_event=False)
            else:
                log_cgroup_info("The {0} controller is not enabled at the root cgroup".format(controller), send_event=False)

    def start_extension_command(self, extension_name, command, cmd_name, timeout, shell, cwd, env, stdout, stderr,
                                error_code=ExtensionErrorCodes.PluginUnknownFailure):
        raise NotImplementedError()


class Cgroup(object):
    MEMORY_CONTROLLER = "memory"

    def __init__(self, cgroup_name):
        self._cgroup_name = cgroup_name

    @staticmethod
    def get_supported_controllers():
        """
        Cgroup version specific. Returns a list of the controllers which the agent supports.
        """
        raise NotImplementedError()

    def check_all_supported_controllers_enabled(self):
        """
        Cgroup version specific. Checks that all agent supported controllers are mounted/enabled.
        """
        raise NotImplementedError()

    def check_in_expected_slice(self, expected_slice):
        """
        Cgroup version specific. Checks that the cgroup is in the expected slice.
        """
        raise NotImplementedError()

    def get_controller_metrics(self, expected_relative_path=None, controller=None):
        """
        Cgroup version specific. Returns a list of the metrics for each agent supported controller which is
        mounted/enabled for the cgroup.
        If expected_relative_path is provided, metrics will only be returned if the cgroup path matches the expected path.
        If controller is provided, only metrics for the provided controller will be returned.
        """
        raise NotImplementedError()

    def get_cgroup_paths(self):
        """
        Cgroup version specific. Returns a list of the paths for the cgroup.
        """
        raise NotImplementedError()


class CgroupV1(Cgroup):
    CPU_CONTROLLER = "cpu,cpuacct"

    def __init__(self, cgroup_name, mount_points, cgroup_paths):
        super(CgroupV1, self).__init__(cgroup_name=cgroup_name)
        self._mount_points = mount_points
        self._cgroup_paths = cgroup_paths

    @staticmethod
    def get_supported_controllers():
        return [CgroupV1.CPU_CONTROLLER, CgroupV1.MEMORY_CONTROLLER]

    def check_all_supported_controllers_enabled(self):
        all_controllers_enabled = True
        for controller in self.get_supported_controllers():
            if self._cgroup_paths.get(controller) is None:
                log_cgroup_warning("{0} is not mounted for {1} cgroup - will not track {0}.".format(controller, self._cgroup_name), send_event=False)
                all_controllers_enabled = False

        return all_controllers_enabled

    def check_in_expected_slice(self, expected_slice):
        in_expected_slice = True
        for controller, path in self._cgroup_paths.items():
            if expected_slice not in path:
                log_cgroup_warning("The {0} controller for the {1} cgroup is not mounted in the expected slice. Expected slice: {2}. Actual controller path: {3}".format(controller, self._cgroup_name, expected_slice, path), send_event=False)
                in_expected_slice = False

        return in_expected_slice

    def get_controller_metrics(self, expected_relative_path=None, controller=None):
        metrics = []
        controllers = [controller] if controller is not None else list(self._cgroup_paths.keys())

        for required_controller in controllers:
            controller_metrics = None
            controller_path = self._cgroup_paths.get(required_controller)

            if expected_relative_path is not None:
                expected_path = ""
                if self._mount_points[required_controller] is not None:
                    expected_path = os.path.join(self._mount_points[required_controller], expected_relative_path)
                if controller_path != expected_path:
                    log_cgroup_warning("The {0} controller is not at the expected path for the {1} cgroup; will not track metrics. Cgroup path:[{2}] Expected:[{3}]".format(required_controller, self._cgroup_name, controller_path, expected_path), send_event=False)
                    continue

            if required_controller == self.CPU_CONTROLLER:
                controller_metrics = CpuMetrics(self._cgroup_name, controller_path)
            elif required_controller == self.MEMORY_CONTROLLER:
                controller_metrics = MemoryMetrics(self._cgroup_name, controller_path)

            if controller_metrics is not None:
                msg = "{0} metrics for cgroup {1}".format(required_controller, controller_metrics)
                log_cgroup_info(msg, send_event=False)
                metrics.append(controller_metrics)

        return metrics

    def get_cgroup_paths(self):
        return list(self._cgroup_paths.values())


class CgroupV2(Cgroup):
    CPU_CONTROLLER = "cpu"

    def __init__(self, cgroup_name, root_cgroup_path, cgroup_path, enabled_controllers):
        super(CgroupV2, self).__init__(cgroup_name)
        self._root_cgroup_path = root_cgroup_path
        self._cgroup_path = cgroup_path
        self._enabled_controllers = enabled_controllers

    @staticmethod
    def get_supported_controllers():
        return [CgroupV2.CPU_CONTROLLER, CgroupV2.MEMORY_CONTROLLER]

    def check_all_supported_controllers_enabled(self):
        all_controllers_enabled = True
        for controller in self.get_supported_controllers():
            if controller not in self._enabled_controllers:
                log_cgroup_warning("The {0} controller is not enabled.".format(controller), send_event=False)
                all_controllers_enabled = False

        return all_controllers_enabled

    def check_in_expected_slice(self, expected_slice):
        if expected_slice not in self._cgroup_path:
            log_cgroup_warning("The {0} cgroup is not in the expected slice. Expected slice: {1}. Actual path: {2}".format(self._cgroup_name, expected_slice, self._cgroup_path), send_event=False)
            return False

        return True

    def get_controller_metrics(self, expected_relative_path=None, controller=None):
        # TODO - Implement controller metrics for CgroupV2
        raise NotImplementedError()

    def get_cgroup_paths(self):
        return [self._cgroup_path]


