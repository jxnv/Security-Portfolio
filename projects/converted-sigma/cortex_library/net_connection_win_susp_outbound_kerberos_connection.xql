// Title: Uncommon Outbound Kerberos Connection
// ID: e54979bd-c5f9-4d6c-967b-a04b19ac4c74
// Status: test
// Level: medium
// Author: Ilyas Ochkov, oscd.community
// Date: 2019-10-24
// Tags: attack.credential-access, attack.t1558, attack.lateral-movement, attack.t1550.003
// Description: Detects uncommon outbound network activity via Kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_remote_port = 88 and Initiated = "true") and not ((action_process_image_path = "C:\\Windows\\System32\\lsass.exe")) and not ((((action_process_image_path = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe" or action_process_image_path = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")) or ((action_process_image_path = "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe" or action_process_image_path = "C:\\Program Files\\Mozilla Firefox\\firefox.exe")) or (action_process_image_path endswith "\\tomcat\\bin\\tomcat8.exe"))))
