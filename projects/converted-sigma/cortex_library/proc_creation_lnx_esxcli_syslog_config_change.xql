// Title: ESXi Syslog Configuration Change Via ESXCLI
// ID: 38eb1dbb-011f-40b1-a126-cf03a0210563
// Status: test
// Level: medium
// Author: Cedric Maurugeon
// Date: 2023-09-04
// Tags: attack.execution, attack.defense-impairment, attack.t1685, attack.t1690, attack.t1059.012
// Description: Detects changes to the ESXi syslog configuration via "esxcli"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/esxcli" and (action_process_image_command_line contains "system" and action_process_image_command_line contains "syslog" and action_process_image_command_line contains "config") and action_process_image_command_line contains " set")
