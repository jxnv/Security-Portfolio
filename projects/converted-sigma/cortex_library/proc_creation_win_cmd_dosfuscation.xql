// Title: Potential Dosfuscation Activity
// ID: a77c1610-fc73-4019-8e29-0f51efc04a51
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-02-15
// Tags: attack.execution, attack.t1059
// Description: Detects possible payload obfuscation via the commandline
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "^^" or action_process_image_command_line contains "^|^" or action_process_image_command_line contains ",;," or action_process_image_command_line contains ";;;;" or action_process_image_command_line contains ";; ;;" or action_process_image_command_line contains "(,(," or action_process_image_command_line contains "%COMSPEC:~" or action_process_image_command_line contains " c^m^d" or action_process_image_command_line contains "^c^m^d" or action_process_image_command_line contains " c^md" or action_process_image_command_line contains " cm^d" or action_process_image_command_line contains "^cm^d" or action_process_image_command_line contains " s^et " or action_process_image_command_line contains " s^e^t " or action_process_image_command_line contains " se^t "))
