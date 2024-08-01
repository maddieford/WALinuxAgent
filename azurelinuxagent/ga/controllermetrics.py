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

import errno
import os
import re
from datetime import timedelta

from azurelinuxagent.common import logger, conf
from azurelinuxagent.common.exception import CGroupsException
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil

_REPORT_EVERY_HOUR = timedelta(hours=1)
_DEFAULT_REPORT_PERIOD = timedelta(seconds=conf.get_cgroup_check_period())

AGENT_NAME_TELEMETRY = "walinuxagent.service"  # Name used for telemetry; it needs to be consistent even if the name of the service changes
AGENT_LOG_COLLECTOR = "azure-walinuxagent-logcollector"


class CounterNotFound(Exception):
    pass


class MetricValue(object):

    """
    Class for defining all the required metric fields to send telemetry.
    """

    def __init__(self, category, counter, instance, value, report_period=_DEFAULT_REPORT_PERIOD):
        self._category = category
        self._counter = counter
        self._instance = instance
        self._value = value
        self._report_period = report_period

    @property
    def category(self):
        return self._category

    @property
    def counter(self):
        return self._counter

    @property
    def instance(self):
        return self._instance

    @property
    def value(self):
        return self._value

    @property
    def report_period(self):
        return self._report_period


class MetricsCategory(object):
    MEMORY_CATEGORY = "Memory"
    CPU_CATEGORY = "CPU"


class MetricsCounter(object):
    PROCESSOR_PERCENT_TIME = "% Processor Time"
    TOTAL_MEM_USAGE = "Total Memory Usage"
    MAX_MEM_USAGE = "Max Memory Usage"
    THROTTLED_TIME = "Throttled Time"
    SWAP_MEM_USAGE = "Swap Memory Usage"
    AVAILABLE_MEM = "Available MBytes"
    USED_MEM = "Used MBytes"
    TOTAL_SEPARATED = "Memory summary"
    MEM_THROTTLED = "Memory Throttled Events"


re_user_system_times = re.compile(r'user (\d+)\nsystem (\d+)\n')
re_usage_time = re.compile(r'usage_usec (\d+)\n')


class ControllerMetrics(object):
    def __init__(self, name, cgroup_path):
        """
        Initialize _data collection for the Memory controller
        :param: name: Name of the CGroup
        :param: cgroup_path: Path of the controller
        :return:
        """
        self.name = name
        self.path = cgroup_path

    def __str__(self):
        return "{0} [{1}]".format(self.name, self.path)

    def _get_cgroup_file(self, file_name):
        return os.path.join(self.path, file_name)

    def _get_file_contents(self, file_name):
        """
        Retrieve the contents to file.

        :param str file_name: Name of file within that metric controller
        :return: Entire contents of the file
        :rtype: str
        """
        parameter_file = self._get_cgroup_file(file_name)

        return fileutil.read_file(parameter_file)

    def _get_parameters(self, parameter_name, first_line_only=False):
        """
        Retrieve the values of a parameter from a controller.
        Returns a list of values in the file.

        :param first_line_only: return only the first line.
        :param str parameter_name: Name of file within that metric controller
        :return: The first line of the file, without line terminator
        :rtype: [str]
        """
        result = []
        try:
            values = self._get_file_contents(parameter_name).splitlines()
            result = values[0] if first_line_only else values
        except IndexError:
            parameter_filename = self._get_cgroup_file(parameter_name)
            logger.error("File {0} is empty but should not be".format(parameter_filename))
            raise CGroupsException("File {0} is empty but should not be".format(parameter_filename))
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise e
            parameter_filename = self._get_cgroup_file(parameter_name)
            raise CGroupsException("Exception while attempting to read {0}".format(parameter_filename), e)
        return result

    def is_active(self):
        try:
            tasks = self._get_parameters("tasks")
            if tasks:
                return len(tasks) != 0
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                # only suppressing file not found exceptions.
                pass
            else:
                logger.periodic_warn(logger.EVERY_HALF_HOUR,
                                     'Could not get list of tasks from "tasks" file in the cgroup: {0}.'
                                     ' Internal error: {1}'.format(self.path, ustr(e)))
        except CGroupsException as e:
            logger.periodic_warn(logger.EVERY_HALF_HOUR,
                                 'Could not get list of tasks from "tasks" file in the cgroup: {0}.'
                                 ' Internal error: {1}'.format(self.path, ustr(e)))
        return False

    def get_tracked_metrics(self, **_):
        """
        Retrieves the current value of the metrics tracked for this cgroup and returns them as an array.

        Note: Agent won't track the metrics if the current cpu ticks less than previous value and returns empty array.
        """
        raise NotImplementedError()

    def get_unit_properties(self):
        """
        Returns a list of the unit properties to collect for the controller.
        """
        raise NotImplementedError()


class CpuMetrics(ControllerMetrics):
    def __init__(self, name, cgroup_path):
        super(CpuMetrics, self).__init__(name, cgroup_path)

        self._osutil = get_osutil()
        self._previous_cgroup_cpu = None
        self._previous_system_cpu = None
        self._current_cgroup_cpu = None
        self._current_system_cpu = None
        self._previous_throttled_time = None
        self._current_throttled_time = None

    def get_throttled_time(self):
        raise NotImplementedError()

    def _cpu_usage_initialized(self):
        return self._current_cgroup_cpu is not None and self._current_system_cpu is not None

    def initialize_cpu_usage(self):
        """
        Sets the initial values of CPU usage. This function must be invoked before calling get_cpu_usage().
        """
        raise NotImplementedError()

    def get_cpu_usage(self):
        """
        Computes the CPU used by the cgroup since the last call to this function.

        The usage is measured as a percentage of utilization of 1 core in the system. For example,
        using 1 core all of the time on a 4-core system would be reported as 100%.

        NOTE: initialize_cpu_usage() must be invoked before calling get_cpu_usage()
        """
        raise NotImplementedError()

    def get_cpu_throttled_time(self, read_previous_throttled_time=True):
        """
        Computes the throttled time (in seconds) since the last call to this function.
        NOTE: initialize_cpu_usage() must be invoked before calling this function
        Compute only current throttled time if read_previous_throttled_time set to False
        """
        raise NotImplementedError()

    def get_tracked_metrics(self, **kwargs):
        tracked = []
        cpu_usage = self.get_cpu_usage()
        if cpu_usage >= float(0):
            tracked.append(
                MetricValue(MetricsCategory.CPU_CATEGORY, MetricsCounter.PROCESSOR_PERCENT_TIME, self.name, cpu_usage))

        if 'track_throttled_time' in kwargs and kwargs['track_throttled_time']:
            throttled_time = self.get_cpu_throttled_time()
            if cpu_usage >= float(0) and throttled_time >= float(0):
                tracked.append(
                    MetricValue(MetricsCategory.CPU_CATEGORY, MetricsCounter.THROTTLED_TIME, self.name, throttled_time))

        return tracked

    def get_unit_properties(self):
        return ["CPUAccounting", "CPUQuotaPerSecUSec"]


class CpuMetricsV1(CpuMetrics):
    def initialize_cpu_usage(self):
        if self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() should be invoked only once")
        self._current_cgroup_cpu = self._get_cpu_ticks(allow_no_such_file_or_directory_error=True)
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()
        self._current_throttled_time = self.get_throttled_time()

    def _get_cpu_ticks(self, allow_no_such_file_or_directory_error=False):
        """
        Returns the number of USER_HZ of CPU time (user and system) consumed by this cgroup.

        If allow_no_such_file_or_directory_error is set to True and cpuacct.stat does not exist the function
        returns 0; this is useful when the function can be called before the cgroup has been created.
        """
        try:
            cpuacct_stat = self._get_file_contents('cpuacct.stat')
        except Exception as e:
            if not isinstance(e, (IOError, OSError)) or e.errno != errno.ENOENT:  # pylint: disable=E1101
                raise CGroupsException("Failed to read cpuacct.stat: {0}".format(ustr(e)))
            if not allow_no_such_file_or_directory_error:
                raise e
            cpuacct_stat = None

        cpu_ticks = 0

        if cpuacct_stat is not None:
            #
            # Sample file:
            #     # cat /sys/fs/cgroup/cpuacct/azure.slice/walinuxagent.service/cpuacct.stat
            #     user 10190
            #     system 3160
            #
            match = re_user_system_times.match(cpuacct_stat)
            if not match:
                raise CGroupsException(
                    "The contents of {0} are invalid: {1}".format(self._get_cgroup_file('cpuacct.stat'), cpuacct_stat))
            cpu_ticks = int(match.groups()[0]) + int(match.groups()[1])

        return cpu_ticks

    def get_cpu_usage(self):
        if not self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() must be invoked before the first call to get_cpu_usage()")

        self._previous_cgroup_cpu = self._current_cgroup_cpu
        self._previous_system_cpu = self._current_system_cpu
        self._current_cgroup_cpu = self._get_cpu_ticks()
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()

        cgroup_delta = self._current_cgroup_cpu - self._previous_cgroup_cpu
        system_delta = max(1, self._current_system_cpu - self._previous_system_cpu)

        return round(100.0 * self._osutil.get_processor_cores() * float(cgroup_delta) / float(system_delta), 3)

    def get_throttled_time(self):
        try:
            with open(os.path.join(self.path, 'cpu.stat')) as cpu_stat:
                #
                # Sample file:
                #
                #   # cat /sys/fs/cgroup/cpuacct/azure.slice/walinuxagent.service/cpu.stat
                #   nr_periods  51660
                #   nr_throttled 19461
                #   throttled_time 1529590856339
                #
                for line in cpu_stat:
                    match = re.match(r'throttled_time\s+(\d+)', line)
                    if match is not None:
                        return int(match.groups()[0])
                raise Exception("Cannot find throttled_time")
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                return 0
            raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))
        except Exception as e:
            raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))

    def get_cpu_throttled_time(self, read_previous_throttled_time=True):
        if not read_previous_throttled_time:
            return float(self.get_throttled_time() / 1E9)

        if not self._cpu_usage_initialized():
            raise CGroupsException(
                "initialize_cpu_usage() must be invoked before the first call to get_throttled_time()")

        self._previous_throttled_time = self._current_throttled_time
        self._current_throttled_time = self.get_throttled_time()

        return float(self._current_throttled_time - self._previous_throttled_time) / 1E9


class CpuMetricsV2(CpuMetrics):
    def initialize_cpu_usage(self):
        if self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() should be invoked only once")
        self._current_cgroup_cpu = self._get_cpu_time(allow_no_such_file_or_directory_error=True)
        self._current_system_cpu = self._osutil.get_total_cpu_ticks_since_boot()
        self._current_throttled_time = self.get_throttled_time()

    def _get_cpu_time(self, allow_no_such_file_or_directory_error=False):
        """
        Returns the CPU time (user and system) consumed by this cgroup in seconds.

        If allow_no_such_file_or_directory_error is set to True and cpu.stat does not exist the function
        returns 0; this is useful when the function can be called before the cgroup has been created.
        """
        try:
            cpu_stat = self._get_file_contents('cpu.stat')
        except Exception as e:
            if not isinstance(e, (IOError, OSError)) or e.errno != errno.ENOENT:  # pylint: disable=E1101
                raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))
            if not allow_no_such_file_or_directory_error:
                raise e
            cpu_stat = None

        cpu_time = 0

        if cpu_stat is not None:
            # Sample file:
            #     # cat /sys/fs/cgroup/azure.slice/azure-walinuxagent.slice/azure-walinuxagent-logcollector.slice/collect-logs.scope/cpu.stat
            #     usage_usec 1990707
            #     user_usec 1939858
            #     system_usec 50848
            #     core_sched.force_idle_usec 0
            #     nr_periods 397
            #     nr_throttled 397
            #     throttled_usec 37994949
            #     nr_bursts 0
            #     burst_usec 0
            #
            match = re_usage_time.match(cpu_stat)
            if not match:
                raise CGroupsException(
                    "The contents of {0} are invalid: {1}".format(self._get_cgroup_file('cpu.stat'), cpu_stat))
            cpu_time = int(match.groups()[0])/1E6

        return cpu_time

    def get_cpu_usage(self):
        if not self._cpu_usage_initialized():
            raise CGroupsException("initialize_cpu_usage() must be invoked before the first call to get_cpu_usage()")

        self._previous_cgroup_cpu = self._current_cgroup_cpu
        self._previous_system_cpu = self._current_system_cpu
        self._current_cgroup_cpu = self._get_cpu_time()
        self._current_system_cpu = self._osutil.get_system_uptime()

        cgroup_delta = self._current_cgroup_cpu - self._previous_cgroup_cpu
        system_delta = max(1, self._current_system_cpu - self._previous_system_cpu)

        return round(100.0 * float(cgroup_delta) / float(system_delta), 3)

    def get_throttled_time(self):
        try:
            with open(os.path.join(self.path, 'cpu.stat')) as cpu_stat:
                #
                # Sample file:
                #
                #   # cat cpu.stat
                #   usage_usec 200161503
                #   user_usec 199388368
                #   system_usec 773134
                #   core_sched.force_idle_usec 0
                #   nr_periods 40059
                #   nr_throttled 40022
                #   throttled_usec 3565247992
                #   nr_bursts 0
                #   burst_usec 0
                #
                for line in cpu_stat:
                    match = re.match(r'throttled_usec\s+(\d+)', line)
                    if match is not None:
                        return int(match.groups()[0])
                raise Exception("Cannot find throttled_usec")
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                return 0
            raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))
        except Exception as e:
            raise CGroupsException("Failed to read cpu.stat: {0}".format(ustr(e)))

    def get_cpu_throttled_time(self, read_previous_throttled_time=True):
        if not read_previous_throttled_time:
            return float(self.get_throttled_time() / 1E6)

        if not self._cpu_usage_initialized():
            raise CGroupsException(
                "initialize_cpu_usage() must be invoked before the first call to get_throttled_time()")

        self._previous_throttled_time = self._current_throttled_time
        self._current_throttled_time = self.get_throttled_time()

        return float(self._current_throttled_time - self._previous_throttled_time) / 1E6


class MemoryMetrics(ControllerMetrics):
    def __init__(self, name, cgroup_path):
        super(MemoryMetrics, self).__init__(name, cgroup_path)

        self._counter_not_found_error_count = 0

    def _get_memory_stat_counter(self, counter_name):
        try:
            with open(os.path.join(self.path, 'memory.stat')) as memory_stat:
                # cat /sys/fs/cgroup/memory/azure.slice/memory.stat
                # cache 67178496
                # rss 42340352
                # rss_huge 6291456
                # swap 0
                for line in memory_stat:
                    re_memory_counter = r'{0}\s+(\d+)'.format(counter_name)
                    match = re.match(re_memory_counter, line)
                    if match is not None:
                        return int(match.groups()[0])
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                raise
            raise CGroupsException("Failed to read memory.stat: {0}".format(ustr(e)))
        except Exception as e:
            raise CGroupsException("Failed to read memory.stat: {0}".format(ustr(e)))

        raise CounterNotFound("Cannot find counter: {0}".format(counter_name))

    def get_memory_usage(self):
        raise NotImplementedError()

    def try_swap_memory_usage(self):
        raise NotImplementedError()

    def get_max_memory_usage(self):
        raise NotImplementedError()

    def get_tracked_metrics(self, **_):
        raise NotImplementedError()

    def get_unit_properties(self):
        return["MemoryAccounting"]


class MemoryMetricsV1(MemoryMetrics):
    def get_memory_usage(self):
        """
        Collect RSS+CACHE from memory.stat cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """

        cache = self._get_memory_stat_counter("cache")
        rss = self._get_memory_stat_counter("rss")
        return cache + rss

    def get_all_slice_metrics_concurrently(self):
        # memory.usage_in_bytes
        # memory.kmem.usage_in_bytes
        # cache 0
        # rss 0
        # rss_huge 0
        # shmem 0
        # mapped_file 0
        # dirty 0
        # writeback 0
        # swap 0
        # pgpgin 0
        # pgpgout 0
        # pgfault 0
        # pgmajfault 0
        # inactive_anon 0
        # active_anon 0
        # inactive_file 0
        # active_file 0
        # unevictable 0
        # hierarchical_memory_limit 9223372036854771712
        # hierarchical_memsw_limit 9223372036854771712
        # total_cache 147230720
        # total_rss 0
        # total_rss_huge 0
        # total_shmem 0
        # total_mapped_file 0
        # total_dirty 53248
        # total_writeback 0
        # total_swap 0
        with open("{0}/memory.usage_in_bytes".format(self.path)) as memory_curr_file, open("{0}/memory.kmem.usage_in_bytes".format(self.path)) as memory_kernel_file, open("{0}/memory.stat".format(self.path)) as memory_stat_file:
            memory_curr = int(memory_curr_file.readlines()[0])
            kernel = int(memory_kernel_file.readlines()[0])
            memory_stat_lines = memory_stat_file.readlines()
            cache = int(re.match(r'total_cache\s+(\d+)', memory_stat_lines[19]).groups()[0])
            rss = int(re.match(r'total_rss\s+(\d+)', memory_stat_lines[20]).groups()[0])
            swap = int(re.match(r'total_swap\s+(\d+)', memory_stat_lines[26]).groups()[0])
            sum_mem = kernel + cache + rss + swap
        return "memory.usage_in_bytes: {0}; memory_summed: {1}; rss: {2}; cache: {3}; kernel: {4}; swap: {5}".format(memory_curr, sum_mem, rss, cache, kernel, swap)


    def get_all_metrics_concurrently(self):
        # memory.usage_in_bytes
        # memory.kmem.usage_in_bytes
        # cache
        # rss
        # swap
        # sum of cache, rss, kernel, swap
        # output = run_command(["cat", "", "", ""])
        # memory_curr = int(output.splitlines()[0])
        # swap = int(output.splitlines()[1])
        # anon = int(re.match(r'anon\s+(\d+)', output.splitlines()[2]).groups()[0])
        # file = int(re.match(r'file\s+(\d+)', output.splitlines()[3]).groups()[0])
        # kernel = int(re.match(r'kernel\s+(\d+)', output.splitlines()[4]).groups()[0])
        # sum_mem = swap + anon + file + kernel
        with open("{0}/memory.usage_in_bytes".format(self.path)) as memory_curr_file, open("{0}/memory.kmem.usage_in_bytes".format(self.path)) as memory_kernel_file, open("{0}/memory.stat".format(self.path)) as memory_stat_file:
            memory_curr = int(memory_curr_file.readlines()[0])
            kernel = int(memory_kernel_file.readlines()[0])
            memory_stat_lines = memory_stat_file.readlines()
            cache = int(re.match(r'cache\s+(\d+)', memory_stat_lines[0]).groups()[0])
            rss = int(re.match(r'rss\s+(\d+)', memory_stat_lines[1]).groups()[0])
            swap = int(re.match(r'swap\s+(\d+)', memory_stat_lines[7]).groups()[0])
            sum_mem = kernel + cache + rss + swap
        return "memory.usage_in_bytes: {0}; memory_summed: {1}; rss: {2}; cache: {3}; kernel: {4}; swap: {5}".format(memory_curr, sum_mem, rss, cache, kernel, swap)

    def try_swap_memory_usage(self):
        """
        Collect SWAP from memory.stat cgroup.

        :return: Memory usage in bytes
        :rtype: int
        Note: stat file is the only place to get the SWAP since other swap related file memory.memsw.usage_in_bytes is for total Memory+SWAP.
        """
        try:
            return self._get_memory_stat_counter("swap")
        except CounterNotFound as e:
            if self._counter_not_found_error_count < 1:
                logger.periodic_info(logger.EVERY_HALF_HOUR,
                                     '{0} from "memory.stat" file in the cgroup: {1}---[Note: This log for informational purpose only and can be ignored]'.format(ustr(e), self.path))
                self._counter_not_found_error_count += 1
            return 0

    def get_max_memory_usage(self):
        """
        Collect memory.max_usage_in_bytes from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = 0
        try:
            usage = int(self._get_parameters('memory.max_usage_in_bytes', first_line_only=True))
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise
            raise CGroupsException("Exception while attempting to read {0}".format("memory.max_usage_in_bytes"), e)

        return usage

    def get_tracked_metrics(self, **_):
        return [
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.TOTAL_MEM_USAGE, self.name,
                        self.get_memory_usage()),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.MAX_MEM_USAGE, self.name,
                        self.get_max_memory_usage(), _REPORT_EVERY_HOUR),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.SWAP_MEM_USAGE, self.name,
                        self.try_swap_memory_usage(), _REPORT_EVERY_HOUR),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.TOTAL_SEPARATED, self.name,
                        self.get_all_metrics_concurrently(), _REPORT_EVERY_HOUR),
        ]


class MemoryMetricsV2(MemoryMetrics):
    def get_memory_usage(self):
        """
        Collect anon+file from memory.stat cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """

        anon = self._get_memory_stat_counter("anon")
        file = self._get_memory_stat_counter("file")
        return anon + file

    def get_memory_throttled(self):
        with open("/sys/fs/cgroup/azure.slice/azure-walinuxagent.slice/azure-walinuxagent-logcollector.slice/collect-logs.scope/memory.events") as scope_events, open("/sys/fs/cgroup/azure.slice/azure-walinuxagent.slice/azure-walinuxagent-logcollector.slice/memory.events") as slice_events:
            scope_throttled = int(re.match(r'high\s+(\d+)', scope_events.readlines()[1]).groups()[0])
            slice_throttled = int(re.match(r'high\s+(\d+)', slice_events.readlines()[1]).groups()[0])
        return "scope mem throttled: {0}; slice mem throttled: {1}".format(scope_throttled, slice_throttled)

    def get_all_metrics_concurrently(self):
        # memory.current
        # swap
        # anon
        # file
        # kernel
        # sum of anon, file, kernel, swap
        # output = run_command(["cat", "", "", ""])
        # memory_curr = int(output.splitlines()[0])
        # swap = int(output.splitlines()[1])
        # anon = int(re.match(r'anon\s+(\d+)', output.splitlines()[2]).groups()[0])
        # file = int(re.match(r'file\s+(\d+)', output.splitlines()[3]).groups()[0])
        # kernel = int(re.match(r'kernel\s+(\d+)', output.splitlines()[4]).groups()[0])
        # sum_mem = swap + anon + file + kernel
        with open("{0}/memory.current".format(self.path)) as memory_curr_file, open("{0}/memory.swap.current".format(self.path)) as memory_swap_file, open("{0}/memory.stat".format(self.path)) as memory_stat_file:
            memory_curr = int(memory_curr_file.readlines()[0])
            swap = int(memory_swap_file.readlines()[0])
            memory_stat_lines = memory_stat_file.readlines()
            anon = int(re.match(r'anon\s+(\d+)', memory_stat_lines[0]).groups()[0])
            file = int(re.match(r'file\s+(\d+)', memory_stat_lines[1]).groups()[0])
            kernel = int(re.match(r'kernel\s+(\d+)', memory_stat_lines[2]).groups()[0])
            sum_mem = swap + anon + file + kernel
        return "memory.current: {0}; memory_summed: {1}; anon: {2}; file: {3}; kernel: {4}; swap: {5}".format(memory_curr, sum_mem, anon, file, kernel, swap)

    def try_swap_memory_usage(self):
        """
        Collect SWAP from memory.swap.current cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = 0
        try:
            usage = int(self._get_parameters('memory.swap.current', first_line_only=True))
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise
            raise CGroupsException("Exception while attempting to read {0}".format("memory.swap.current"), e)

        return usage

    def get_max_memory_usage(self):
        """
        Collect memory.peak from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = 0
        try:
            usage = int(self._get_parameters('memory.peak', first_line_only=True))
        except Exception as e:
            if isinstance(e, (IOError, OSError)) and e.errno == errno.ENOENT:  # pylint: disable=E1101
                raise
            raise CGroupsException("Exception while attempting to read {0}".format("memory.peak"), e)

        return usage

    def get_tracked_metrics(self, **_):
        return [
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.TOTAL_MEM_USAGE, self.name,
                        self.get_memory_usage()),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.MAX_MEM_USAGE, self.name,
                        self.get_max_memory_usage(), _REPORT_EVERY_HOUR),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.SWAP_MEM_USAGE, self.name,
                        self.try_swap_memory_usage(), _REPORT_EVERY_HOUR),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.MEM_THROTTLED, self.name,
                        self.get_memory_throttled(), _REPORT_EVERY_HOUR),
            MetricValue(MetricsCategory.MEMORY_CATEGORY, MetricsCounter.TOTAL_SEPARATED, self.name,
                        self.get_all_metrics_concurrently(), _REPORT_EVERY_HOUR),
        ]
