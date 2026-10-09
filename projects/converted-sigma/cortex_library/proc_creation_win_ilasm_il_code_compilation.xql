// Title: C# IL Code Compilation Via Ilasm.EXE
// ID: 850d55f9-6eeb-4492-ad69-a72338f65ba4
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-05-07
// Tags: attack.execution, attack.stealth, attack.t1127
// Description: Detects the use of "Ilasm.EXE" in order to compile C# intermediate (IL) code to EXE or DLL.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " /dll" or action_process_image_command_line contains " /exe")) and ((action_process_image_path endswith "\\ilasm.exe") or (action_process_image_name = "ilasm.exe")))
