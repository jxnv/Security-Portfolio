// Title: Shell Invocation via Apt - Linux
// ID: bb382fd5-b454-47ea-a264-1828e4c766d6
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-28
// Tags: attack.discovery, attack.t1083
// Description: Detects the use of the "apt" and "apt-get" commands to execute a shell or proxy commands.
// Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/apt" or action_process_image_path endswith "/apt-get") and action_process_image_command_line contains "APT::Update::Pre-Invoke::=")
