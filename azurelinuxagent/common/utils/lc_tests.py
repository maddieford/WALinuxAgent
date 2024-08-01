import re
from pathlib import Path
import matplotlib.pyplot as plt

waagent_log_path = Path('/home/maddieford/tmp/cgroupsv2/logcollector-investigation/experiments/v2_160M_limit_scope_only/waagent.log')
lc_start_regex = r'.*LogCollector Running log collector mode normal'
lc_end_regex = r'.*CollectLogsHandler ExtHandler Successfully uploaded logs.'
memory_slice_regex_v2 = r'.*Memory slice summary \[azure-walinuxagent-logcollector\] = memory.current: (\d+); memory_summed: (\d+); anon: (\d+); file: (\d+); kernel: (\d+); swap: (\d+)'
memory_slice_regex_v1 = r'.*Memory slice summary \[azure-walinuxagent-logcollector\] = memory.usage_in_bytes: (\d+); memory_summed: (\d+); rss: (\d+); cache: (\d+); kernel: (\d+); swap: (\d+)'
memory_summary_regex = r'.*Memory summary \[azure-walinuxagent-logcollector\] = (.*)'
memory_throttled_regex = r'.*Memory Throttled.*= (.*)'
memory_regex_v2 = r'memory.current: (\d+); memory_summed: (\d+); anon: (\d+); file: (\d+); kernel: (\d+); swap: (\d+)'
memory_regex_v1 = r'memory.usage_in_bytes: (\d+); memory_summed: (\d+); rss: (\d+); cache: (\d+); kernel: (\d+); swap: (\d+)'
memory_throttled_summary_regex = r'scope mem throttled: (\d+); slice mem throttled: (\d+)'

total_memory_curr_list = []
total_memory_sum_list = []
total_memory_anon_list = []
total_memory_file_list = []
total_memory_kernel_list = []
total_memory_swap_list = []
total_scope_memory_throttled_events = []
total_slice_memory_throttled_events = []

ax = plt.gca()
ax.set_ylim([0, 180])
# plt.title("anon memory")
# plt.ylabel("anon memory usage (MB)")
# plt.xlabel("Time since start of run (s)")
plt.title("Slice memory usage")
plt.ylabel("slice memory usage (MB)")
plt.xlabel("log collector run")

with open(waagent_log_path) as waagent_log:
    run_count = 1
    memory_curr_list = []
    memory_sum_list = []
    memory_anon_list = []
    memory_anon_time = []
    memory_file_list = []
    memory_file_time = []
    memory_kernel_list = []
    memory_swap_list = []
    memory_time = 0.0
    slice_mem_runs_x_axis = [0]
    slice_mem_sum_y_axis = [0]
    slice_mem_anon_y_axis = [0]
    slice_mem_file_y_axis = [0]
    slice_mem_kernel_y_axis = [0]
    slice_mem_swap_y_axis = [0]

    max_cache_mem = 0

    for line in waagent_log:
        lc_start_match = re.match(lc_start_regex, line)
        if lc_start_match is not None:
            print("Log collector run: {0}".format(run_count))
            memory_curr_list = []
            memory_sum_list = []
            memory_anon_list = []
            memory_file_time = []
            memory_time = 0.0
            memory_file_list = []
            memory_kernel_list = []
            memory_swap_list = []
            scope_memory_throttled = []
            slice_memory_throttled = []

        memory_slice_match = re.match(memory_slice_regex_v2, line)
        if memory_slice_match is not None:
            print("Memory counters in the slice after run...")
            slice_mem_curr = memory_slice_match.groups()[0]
            slice_mem_sum = memory_slice_match.groups()[1]
            slice_mem_anon = memory_slice_match.groups()[2]
            slice_mem_file = memory_slice_match.groups()[3]
            slice_mem_kernel = memory_slice_match.groups()[4]
            slice_mem_swap = memory_slice_match.groups()[5]
            if run_count < 101:
                slice_mem_runs_x_axis.append(run_count)
                slice_mem_sum_y_axis.append(int(slice_mem_sum)/(1024*1024))
                slice_mem_anon_y_axis.append(int(slice_mem_anon)/(1024*1024))
                slice_mem_file_y_axis.append(int(slice_mem_file)/(1024*1024))
                slice_mem_kernel_y_axis.append(int(slice_mem_kernel)/(1024*1024))
                slice_mem_swap_y_axis.append(int(slice_mem_swap)/(1024*1024))
            print("memory.current={0}; calculated memory sum={1}; anon memory={2}; file memory={3}; kernel memory={4}; swap memory={5}".format(slice_mem_curr, slice_mem_sum, slice_mem_anon, slice_mem_file, slice_mem_kernel, slice_mem_swap))
            continue

        lc_end_match = re.match(lc_end_regex, line)
        if lc_end_match is not None:
            total_memory_curr_list.extend(memory_curr_list)
            print("memory.current: max={0}; avg={1}; min={2}".format(max(memory_curr_list),
                                                                      int(sum(memory_curr_list) / len(memory_curr_list)),
                                                                      min(memory_curr_list)))
            total_memory_sum_list.extend(memory_sum_list)
            print("calculated memory sum: max={0}; avg={1}; min={2}".format(max(memory_sum_list),
                                                                      int(sum(memory_sum_list) / len(memory_sum_list)),
                                                                      min(memory_sum_list)))
            total_memory_anon_list.extend(memory_anon_list)
            print("anon memory: max={0}; avg={1}; min={2}".format(max(memory_anon_list),
                                                                  int(sum(memory_anon_list) / len(memory_anon_list)),
                                                                  min(memory_anon_list)))
            total_memory_file_list.extend(memory_file_list)
            print("file memory: max={0}; avg={1}; min={2}".format(max(memory_file_list),
                                                                  int(sum(memory_file_list) / len(memory_file_list)),
                                                                  min(memory_file_list)))
            total_memory_kernel_list.extend(memory_kernel_list)
            print("kernel memory: max={0}; avg={1}; min={2}".format(max(memory_kernel_list),
                                                                  int(sum(memory_kernel_list) / len(memory_kernel_list)),
                                                                  min(memory_kernel_list)))
            total_memory_swap_list.extend(memory_swap_list)
            print("swap memory: max={0}; avg={1}; min={2}".format(max(memory_swap_list),
                                                                  int(sum(memory_swap_list) / len(memory_swap_list)),
                                                                  min(memory_swap_list)))
            total_scope_memory_throttled_events.append(max(scope_memory_throttled)-min(scope_memory_throttled))
            total_slice_memory_throttled_events.append(max(slice_memory_throttled)-min(slice_memory_throttled))
            print("memory throttled events: scope={0}; slice={1}".format(max(scope_memory_throttled)-min(scope_memory_throttled), max(slice_memory_throttled)-min(slice_memory_throttled)))
            print()

            if run_count < 17:
                memory_file_list_transformed = [x/(1024*1024) for x in memory_anon_list]
                # plt.plot(memory_file_time, memory_file_list_transformed, label="run {0}".format(run_count))
            run_count += 1

        memory_summary_match = re.match(memory_summary_regex, line)
        if memory_summary_match is not None:
            memory_summary = memory_summary_match.groups()[0]
            memory_match = re.match(memory_regex_v2, memory_summary)
            memory_curr_list.append(int(memory_match.groups()[0].rstrip()))
            memory_sum_list.append(int(memory_match.groups()[1].rstrip()))
            memory_anon_list.append(int(memory_match.groups()[2].rstrip()))
            memory_file_time.append(memory_time)
            memory_time += 0.5
            memory_file_list.append(int(memory_match.groups()[3].rstrip()))
            memory_kernel_list.append(int(memory_match.groups()[4].rstrip()))
            memory_swap_list.append(int(memory_match.groups()[5].rstrip()))

            if int(memory_match.groups()[1].rstrip()) > max_cache_mem:
                max_cache_mem = int(memory_match.groups()[1].rstrip())

        memory_throttled_match = re.match(memory_throttled_regex, line)
        if memory_throttled_match is not None:
            memory_throttled_summary = memory_throttled_match.groups()[0]
            memory_throttled = re.match(memory_throttled_summary_regex, memory_throttled_summary)
            scope_memory_throttled.append(int(memory_throttled.groups()[0]))
            slice_memory_throttled.append(int(memory_throttled.groups()[1]))


print("TOTAL RESULTS")
print("memory.current: max={0}; avg={1}; min={2}".format(max(total_memory_curr_list)/((1024*1024)),
                                                          int(sum(total_memory_curr_list) / len(total_memory_curr_list))/((1024*1024)),
                                                          min(total_memory_curr_list)/((1024*1024))))
print("calculated memory sum: max={0}; avg={1}; min={2}".format(max(total_memory_sum_list)/((1024*1024)),
                                                          int(sum(total_memory_sum_list) / len(total_memory_sum_list))/((1024*1024)),
                                                          min(total_memory_sum_list)/((1024*1024))))
print("anon memory: max={0}; avg={1}; min={2}".format(max(total_memory_anon_list)/((1024*1024)),
                                                      int(sum(total_memory_anon_list) / len(total_memory_anon_list))/((1024*1024)),
                                                      min(total_memory_anon_list)/((1024*1024))))
print("file memory: max={0}; avg={1}; min={2}".format(max(total_memory_file_list)/((1024*1024)),
                                                      int(sum(total_memory_file_list) / len(total_memory_file_list))/((1024*1024)),
                                                      min(total_memory_file_list)/((1024*1024))))
print("kernel memory: max={0}; avg={1}; min={2}".format(max(total_memory_kernel_list)/((1024*1024)),
                                                      int(sum(total_memory_kernel_list) / len(total_memory_kernel_list))/((1024*1024)),
                                                      min(total_memory_kernel_list)/((1024*1024))))
print("swap memory: max={0}; avg={1}; min={2}".format(max(total_memory_swap_list)/((1024*1024)),
                                                      int(sum(total_memory_swap_list) / len(total_memory_swap_list))/((1024*1024)),
                                                      min(total_memory_swap_list)/((1024*1024))))
print("scope memory throttled: max={0}; avg={1}; min={2}".format(max(total_scope_memory_throttled_events), int(sum(total_scope_memory_throttled_events)/len(total_scope_memory_throttled_events)), min(total_scope_memory_throttled_events)))
print("slice memory throttled: max={0}; avg={1}; min={2}".format(max(total_slice_memory_throttled_events), int(sum(total_slice_memory_throttled_events)/len(total_slice_memory_throttled_events)), min(total_slice_memory_throttled_events)))

plt.plot(slice_mem_runs_x_axis, slice_mem_sum_y_axis, label="total")
plt.plot(slice_mem_runs_x_axis, slice_mem_anon_y_axis, label="anon")
plt.plot(slice_mem_runs_x_axis, slice_mem_file_y_axis, label="file")
plt.plot(slice_mem_runs_x_axis, slice_mem_kernel_y_axis, label="kernel")
plt.plot(slice_mem_runs_x_axis, slice_mem_swap_y_axis, label="swap")
print("max slice mem: {0}".format(max(slice_mem_sum_y_axis)*(1024*1024)))

# print("max total mem: {0}".format(max_cache_mem))
plt.legend(loc='center left', bbox_to_anchor=(0.92, 0.5))
plt.show()