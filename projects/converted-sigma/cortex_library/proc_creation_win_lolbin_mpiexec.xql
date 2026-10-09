// Title: MpiExec Lolbin
// ID: 729ce0ea-5d8f-4769-9762-e35de441586d
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-11
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: Detects a certain command line flag combination used by mpiexec.exe LOLBIN from HPC pack that can be used to execute any other binary
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\mpiexec.exe") or (Hashes contains "IMPHASH=d8b52ef6aaa3a81501bdfff9dbb96217")) and ((action_process_image_command_line contains " /n 1 " or action_process_image_command_line contains " -n 1 ")))
