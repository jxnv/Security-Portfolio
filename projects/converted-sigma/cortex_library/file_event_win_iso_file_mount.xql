// Title: ISO File Created Within Temp Folders
// ID: 2f9356ae-bf43-41b8-b858-4496d83b2acb
// Status: test
// Level: high
// Author: @sam0x90
// Date: 2022-07-30
// Tags: attack.initial-access, attack.t1566.001
// Description: Detects the creation of a ISO file in the Outlook temp folder or in the Appdata temp folder. Typical of Qakbot TTP from end-July 2022.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path contains "\\AppData\\Local\\Temp\\" and action_file_path contains ".zip\\") and action_file_path endswith ".iso") or (action_file_path contains "\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\" and action_file_path endswith ".iso"))
