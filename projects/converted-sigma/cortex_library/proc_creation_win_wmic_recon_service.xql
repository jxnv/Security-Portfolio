// Title: Service Reconnaissance Via Wmic.EXE
// ID: 76f55eaa-d27f-4213-9d45-7b0e4b60bbae
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-14
// Tags: attack.execution, attack.t1047
// Description: An adversary might use WMI to check if a certain remote service is running on a remote device.
// When the test completes, a service information will be displayed on the screen if it exists.
// A common feedback message is that "No instance(s) Available" if the service queried is not running.
// A common error message is "Node - (provided IP or default) ERROR Description =The RPC server is unavailable" if the provided remote host is unreachable
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "service") and ((action_process_image_path endswith "\\WMIC.exe") or (action_process_image_name = "wmic.exe"))) and not ((((action_process_image_command_line contains "stopservice" or action_process_image_command_line contains "startservice")) or ((action_process_image_command_line contains "Change" or action_process_image_command_line contains "Create" or action_process_image_command_line contains "Delete" or action_process_image_command_line contains "PauseService" or action_process_image_command_line contains "ResumeService" or action_process_image_command_line contains "SetSecurityDescriptor" or action_process_image_command_line contains "StartService" or action_process_image_command_line contains "StopService" or action_process_image_command_line contains "UserControlService")))))
