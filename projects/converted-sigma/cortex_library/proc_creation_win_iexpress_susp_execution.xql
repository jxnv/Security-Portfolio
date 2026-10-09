// Title: Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location
// ID: b2b048b0-7857-4380-b0fb-d3f0ab820b71
// Status: test
// Level: high
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk, Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-02-05
// Tags: attack.stealth, attack.t1218
// Description: Detects the use of iexpress.exe to create binaries via Self Extraction Directive (SED) files located in potentially suspicious locations.
// This behavior has been observed in-the-wild by different threat actors.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " /n ") and ((action_process_image_path endswith "\\iexpress.exe") or (action_process_image_name = "IEXPRESS.exe")) and ((action_process_image_command_line contains ":\\ProgramData\\" or action_process_image_command_line contains ":\\Temp\\" or action_process_image_command_line contains ":\\Windows\\System32\\Tasks\\" or action_process_image_command_line contains ":\\Windows\\Tasks\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp\\")))
