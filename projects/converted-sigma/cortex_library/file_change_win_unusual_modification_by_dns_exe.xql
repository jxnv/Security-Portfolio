// Title: Unusual File Modification by dns.exe
// ID: 9f383dc0-fdeb-4d56-acbc-9f9f4f8f20f3
// Status: test
// Level: high
// Author: Tim Rauch (Nextron Systems), Elastic (idea)
// Date: 2022-09-27
// Tags: attack.persistence, attack.initial-access, attack.t1133
// Description: Detects an unexpected file being modified by dns.exe which my indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\dns.exe") and not ((action_file_path endswith "\\dns.log")))
