// Title: ESXi VM List Discovery Via ESXCLI
// ID: 5f1573a7-363b-4114-9208-ad7a61de46eb
// Status: test
// Level: medium
// Author: Cedric Maurugeon
// Date: 2023-09-04
// Tags: attack.discovery, attack.execution, attack.t1033, attack.t1007, attack.t1059.012
// Description: Detects execution of the "esxcli" command with the "vm" flag in order to retrieve information about the installed VMs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/esxcli" and action_process_image_command_line contains "vm process" and action_process_image_command_line endswith " list")
