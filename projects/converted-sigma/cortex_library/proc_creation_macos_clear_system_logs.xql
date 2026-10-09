// Title: Indicator Removal on Host - Clear Mac System Logs
// ID: acf61bd8-d814-4272-81f0-a7a269aa69aa
// Status: test
// Level: medium
// Author: remotephone, oscd.community
// Date: 2020-10-11
// Tags: attack.defense-impairment, attack.t1685.006
// Description: Detects deletion of local audit logs
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "/rm" or action_process_image_path endswith "/unlink" or action_process_image_path endswith "/shred")) and ((action_process_image_command_line contains "/var/log") or ((action_process_image_command_line contains "/Users/" and action_process_image_command_line contains "/Library/Logs/"))))
