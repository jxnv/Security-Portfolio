// Title: Container Residence Discovery Via Proc Virtual FS
// ID: 746c86fb-ccda-4816-8997-01386263acc4
// Status: test
// Level: low
// Author: Seth Hanford
// Date: 2023-08-23
// Tags: attack.discovery, attack.t1082
// Description: Detects potential container discovery via listing of certain kernel features in the "/proc" virtual filesystem
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "awk" or action_process_image_path endswith "/cat" or action_process_image_path endswith "grep" or action_process_image_path endswith "/head" or action_process_image_path endswith "/less" or action_process_image_path endswith "/more" or action_process_image_path endswith "/nl" or action_process_image_path endswith "/tail")) and ((action_process_image_command_line contains "/proc/2/") or (action_process_image_command_line contains "/proc/" and (action_process_image_command_line endswith "/cgroup" or action_process_image_command_line endswith "/sched"))))
