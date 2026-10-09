// Title: Unusual File Download from Direct IP Address
// ID: 025bd229-fd1f-4fdb-97ab-20006e1a5368
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
// Date: 2022-09-07
// Tags: attack.stealth, attack.t1564.004
// Description: Detects the download of suspicious file type from URLs with IP
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Contents ~= "http[s]?://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" and (action_file_path contains ".ps1:Zone" or action_file_path contains ".bat:Zone" or action_file_path contains ".exe:Zone" or action_file_path contains ".vbe:Zone" or action_file_path contains ".vbs:Zone" or action_file_path contains ".dll:Zone" or action_file_path contains ".one:Zone" or action_file_path contains ".cmd:Zone" or action_file_path contains ".hta:Zone" or action_file_path contains ".xll:Zone" or action_file_path contains ".lnk:Zone"))
