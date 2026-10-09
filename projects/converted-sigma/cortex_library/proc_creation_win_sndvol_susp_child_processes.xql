// Title: Uncommon Child Processes Of SndVol.exe
// ID: ba42babc-0666-4393-a4f7-ceaf5a69191e
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems)
// Date: 2023-06-09
// Tags: attack.execution
// Description: Detects potentially uncommon child processes of SndVol.exe (the Windows volume mixer)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\SndVol.exe") and not ((action_process_image_path endswith "\\rundll32.exe" and action_process_image_command_line contains " shell32.dll,Control_RunDLL ")))
