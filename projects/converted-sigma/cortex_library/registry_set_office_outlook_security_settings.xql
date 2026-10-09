// Title: Outlook Security Settings Updated - Registry
// ID: c3cefdf4-6703-4e1c-bad8-bf422fc5015a
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-12-28
// Tags: attack.persistence, attack.t1137
// Description: Detects changes to the registry values related to outlook security settings
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\SOFTWARE\\Microsoft\\Office\\" and TargetObject contains "\\Outlook\\Security\\")) and not (((action_process_image_path startswith "C:\\Program Files\\Microsoft Office\\" or action_process_image_path startswith "C:\\Program Files (x86)\\Microsoft Office\\") and action_process_image_path endswith "\\OUTLOOK.EXE")))
