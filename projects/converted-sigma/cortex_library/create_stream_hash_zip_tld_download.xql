// Title: Potentially Suspicious File Download From ZIP TLD
// ID: 0bb4bbeb-fe52-4044-b40c-430a04577ebe
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2023-05-18
// Tags: attack.stealth
// Description: Detects the download of a file with a potentially suspicious extension from a .zip top level domain.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Contents contains ".zip/" and (action_file_path contains ".bat:Zone" or action_file_path contains ".dat:Zone" or action_file_path contains ".dll:Zone" or action_file_path contains ".doc:Zone" or action_file_path contains ".docm:Zone" or action_file_path contains ".exe:Zone" or action_file_path contains ".hta:Zone" or action_file_path contains ".pptm:Zone" or action_file_path contains ".ps1:Zone" or action_file_path contains ".rar:Zone" or action_file_path contains ".rtf:Zone" or action_file_path contains ".sct:Zone" or action_file_path contains ".vbe:Zone" or action_file_path contains ".vbs:Zone" or action_file_path contains ".ws:Zone" or action_file_path contains ".wsf:Zone" or action_file_path contains ".xll:Zone" or action_file_path contains ".xls:Zone" or action_file_path contains ".xlsm:Zone" or action_file_path contains ".zip:Zone"))
