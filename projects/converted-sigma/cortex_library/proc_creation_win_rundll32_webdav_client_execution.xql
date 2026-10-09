// Title: WebDav Client Execution Via Rundll32.EXE
// ID: 2dbd9d3d-9e27-42a8-b8df-f13825c6c3d5
// Status: test
// Level: medium
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2020-05-02
// Tags: attack.exfiltration, attack.t1048.003
// Description: Detects "svchost.exe" spawning "rundll32.exe" with command arguments like "C:\windows\system32\davclnt.dll,DavSetCookie".
// This could be an indicator of exfiltration or use of WebDav to launch code (hosted on a WebDav server).
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "C:\\windows\\system32\\davclnt.dll,DavSetCookie") and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")) and (actor_process_image_path endswith "\\svchost.exe"))
