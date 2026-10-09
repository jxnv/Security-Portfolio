// Title: Remote File Download Via Findstr.EXE
// ID: 587254ee-a24b-4335-b3cd-065c0f1f4baa
// Status: test
// Level: medium
// Author: Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)
// Date: 2020-10-05
// Tags: attack.credential-access, attack.command-and-control, attack.stealth, attack.t1218, attack.t1564.004, attack.t1552.001, attack.t1105
// Description: Detects execution of "findstr" with specific flags and a remote share path. This specific set of CLI flags would allow "findstr" to download the content of the file located on the remote share as described in the LOLBAS entry.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "findstr") or (action_process_image_path endswith "findstr.exe") or (action_process_image_name = "FINDSTR.EXE")) and ((action_process_image_command_line contains " -v ") and (action_process_image_command_line contains " -l ") and (action_process_image_command_line contains "\\\\\\\\")))
