// Title: Schtasks Creation Or Modification With SYSTEM Privileges
// ID: 89ca78fd-b37c-4310-b3d3-81a023f83936
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-28
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
// Description: Detects the creation or update of a scheduled task to run with "NT AUTHORITY\SYSTEM" privileges
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\schtasks.exe" and (action_process_image_command_line contains " /change " or action_process_image_command_line contains " /create ")) and (action_process_image_command_line contains "/ru ") and ((action_process_image_command_line contains "NT AUT" or action_process_image_command_line contains " SYSTEM "))) and not ((((action_process_image_command_line contains "/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR " or action_process_image_command_line contains ":\\Program Files (x86)\\Avira\\System Speedup\\setup\\avira_speedup_setup.exe" or action_process_image_command_line contains "/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART\" /RL HIGHEST")) or ((action_process_image_command_line contains "Subscription Heartbeat" and action_process_image_command_line contains "\\HeartbeatConfig.xml" and action_process_image_command_line contains "\\Microsoft Shared\\OFFICE")) or (action_process_image_path endswith "\\schtasks.exe" and (action_process_image_command_line contains "/TN TVInstallRestore" and action_process_image_command_line contains "\\TeamViewer_.exe")))))
