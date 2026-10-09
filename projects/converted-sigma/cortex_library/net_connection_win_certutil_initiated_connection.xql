// Title: Uncommon Network Connection Initiated By Certutil.EXE
// ID: 0dba975d-a193-4ed1-a067-424df57570d1
// Status: test
// Level: high
// Author: frack113, Florian Roth (Nextron Systems)
// Date: 2022-09-02
// Tags: attack.command-and-control, attack.t1105
// Description: Detects a network connection initiated by the certutil.exe utility.
// Attackers can abuse the utility in order to download malware or additional payloads.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\certutil.exe" and Initiated = "true" and (action_remote_port = 80 or action_remote_port = 135 or action_remote_port = 443 or action_remote_port = 445))
