// Title: Suspicious Outbound SMTP Connections
// ID: 9976fa64-2804-423c-8a5b-646ade840773
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-07
// Tags: attack.exfiltration, attack.t1048.003
// Description: Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.
// The data may also be sent to an alternate network location from the main command and control server.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_remote_port = 25 or action_remote_port = 587 or action_remote_port = 465 or action_remote_port = 2525) and Initiated = "true") and not ((((action_process_image_path endswith "\\thunderbird.exe" or action_process_image_path endswith "\\outlook.exe")) or (action_process_image_path startswith "C:\\Program Files\\Microsoft\\Exchange Server\\") or (action_process_image_path startswith "C:\\Program Files\\WindowsApps\\microsoft.windowscommunicationsapps_" and action_process_image_path endswith "\\HxTsr.exe"))))
