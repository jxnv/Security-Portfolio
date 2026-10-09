// Title: Suspicious Rundll32 Activity Invoking Sys File
// ID: 731231b9-0b5d-4219-94dd-abb6959aa7ea
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-03-05
// Tags: attack.stealth, attack.t1218.011
// Description: Detects suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "rundll32.exe") and ((action_process_image_command_line contains ".sys," or action_process_image_command_line contains ".sys ")))
