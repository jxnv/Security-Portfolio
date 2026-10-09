// Title: Use of VSIISExeLauncher.exe
// ID: 18749301-f1c5-4efc-a4c3-276ff1f5b6f8
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-09
// Tags: attack.execution, attack.stealth, attack.t1127
// Description: The "VSIISExeLauncher.exe" binary part of the Visual Studio/VS Code can be used to execute arbitrary binaries
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -p " or action_process_image_command_line contains " -a ")) and ((action_process_image_path endswith "\\VSIISExeLauncher.exe") or (action_process_image_name = "VSIISExeLauncher.exe")))
