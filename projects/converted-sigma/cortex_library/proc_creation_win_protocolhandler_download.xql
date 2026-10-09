// Title: File Download Using ProtocolHandler.exe
// ID: 104cdb48-a7a8-4ca7-a453-32942c6e5dcb
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-07-13
// Tags: attack.stealth, attack.t1218
// Description: Detects usage of "ProtocolHandler" to download files. Downloaded files will be located in the cache folder (for example - %LOCALAPPDATA%\Microsoft\Windows\INetCache\IE)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "ftp://" or action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://")) and ((action_process_image_path endswith "\\protocolhandler.exe") or (action_process_image_name = "ProtocolHandler.exe")))
