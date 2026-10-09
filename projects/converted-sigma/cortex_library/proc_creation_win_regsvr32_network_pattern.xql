// Title: Potentially Suspicious Regsvr32 HTTP/FTP Pattern
// ID: 867356ee-9352-41c9-a8f2-1be690d78216
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2023-05-24
// Tags: attack.stealth, attack.t1218.010
// Description: Detects regsvr32 execution to download/install/register new DLLs that are hosted on Web or FTP servers.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " /i" or action_process_image_command_line contains " -i")) and ((action_process_image_path endswith "\\regsvr32.exe") or (action_process_image_name = "REGSVR32.EXE")) and ((action_process_image_command_line contains "ftp" or action_process_image_command_line contains "http")))
