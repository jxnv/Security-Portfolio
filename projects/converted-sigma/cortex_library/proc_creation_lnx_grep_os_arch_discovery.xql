// Title: OS Architecture Discovery Via Grep
// ID: d27ab432-2199-483f-a297-03633c05bae6
// Status: test
// Level: low
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-06-02
// Tags: attack.discovery, attack.t1082
// Description: Detects the use of grep to identify information about the operating system architecture. Often combined beforehand with the execution of "uname" or "cat /proc/cpuinfo"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line endswith "aarch64" or action_process_image_command_line endswith "arm" or action_process_image_command_line endswith "i386" or action_process_image_command_line endswith "i686" or action_process_image_command_line endswith "mips" or action_process_image_command_line endswith "x86_64")) and (action_process_image_path endswith "/grep"))
