// Title: Potential PowerShell Command Line Obfuscation
// ID: d7bcd677-645d-4691-a8d4-7a5602b780d1
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton (fp)
// Date: 2020-10-15
// Tags: attack.execution, attack.stealth, attack.t1027, attack.t1059.001
// Description: Detects the PowerShell command lines with special characters
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((action_process_image_command_line ~= "\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+") or (action_process_image_command_line ~= "\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{") or (action_process_image_command_line ~= "\\^.*\\^.*\\^.*\\^.*\\^") or (action_process_image_command_line ~= "`.*`.*`.*`.*`"))) and not (((actor_process_image_path = "C:\\Program Files\\Amazon\\SSM\\ssm-document-worker.exe") or ((action_process_image_command_line contains "new EventSource(\"Microsoft.Windows.Sense.Client.Management\"" or action_process_image_command_line contains "public static extern bool InstallELAMCertificateInfo(SafeFileHandle handle);")))))
