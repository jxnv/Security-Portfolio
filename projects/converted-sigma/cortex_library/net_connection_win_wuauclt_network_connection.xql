// Title: Potentially Suspicious Wuauclt Network Connection
// ID: c649a6c7-cd8c-4a78-9c04-000fc76df954
// Status: test
// Level: medium
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2020-10-12
// Tags: attack.stealth, attack.t1218
// Description: Detects the use of the Windows Update Client binary (wuauclt.exe) to proxy execute code and making network connections.
// One could easily make the DLL spawn a new process and inject to it to proxy the network connection and bypass this rule.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path contains "wuauclt" and action_process_image_command_line contains " /RunHandlerComServer") and not (((action_process_image_command_line = "") or (action_process_image_command_line = null) or ((incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "10.0.0.0/8") or incidr(action_remote_ip, "169.254.0.0/16") or incidr(action_remote_ip, "172.16.0.0/12") or incidr(action_remote_ip, "192.168.0.0/16") or incidr(action_remote_ip, "::1/128") or incidr(action_remote_ip, "fe80::/10") or incidr(action_remote_ip, "fc00::/7"))) or ((incidr(action_remote_ip, "20.184.0.0/13") or incidr(action_remote_ip, "20.192.0.0/10") or incidr(action_remote_ip, "23.79.0.0/16") or incidr(action_remote_ip, "51.10.0.0/15") or incidr(action_remote_ip, "51.103.0.0/16") or incidr(action_remote_ip, "51.104.0.0/15") or incidr(action_remote_ip, "52.224.0.0/11"))) or ((action_process_image_command_line contains ":\\Windows\\UUS\\Packages\\Preview\\amd64\\updatedeploy.dll /ClassId" or action_process_image_command_line contains ":\\Windows\\UUS\\amd64\\UpdateDeploy.dll /ClassId")) or ((action_process_image_command_line contains ":\\Windows\\WinSxS\\" and action_process_image_command_line contains "\\UpdateDeploy.dll /ClassId ")))))
