// Title: File Download Via InstallUtil.EXE
// ID: 75edd216-1939-4c73-8d61-7f3a0d85b5cc
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-19
// Tags: attack.stealth, attack.t1218
// Description: Detects use of .NET InstallUtil.exe in order to download arbitrary files. The files will be written to "%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "ftp://" or action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://")) and ((action_process_image_path endswith "\\InstallUtil.exe") or (action_process_image_name = "InstallUtil.exe")))
