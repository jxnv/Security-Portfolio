// Title: HackTool - Dumpert Process Dumper Execution
// ID: 2704ab9e-afe2-4854-a3b1-0c0706d03578
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2020-02-04
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Hashes contains "IMPHASH=09D278F9DE118EF09163C6140255C690") or ((action_process_image_command_line contains "Dumpert.dll" or action_process_image_command_line contains "Dumpert.exe")))
