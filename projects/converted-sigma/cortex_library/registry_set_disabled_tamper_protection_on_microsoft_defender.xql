// Title: Disable Tamper Protection on Windows Defender
// ID: 93d298a1-d28f-47f1-a468-d971e7796679
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-08-04
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects disabling Windows Defender Tamper Protection
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Microsoft\\Windows Defender\\Features\\TamperProtection" and Details = "DWORD (0x00000000)") and not (((action_process_image_path startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" and action_process_image_path endswith "\\MsMpEng.exe") or (action_process_image_path = "C:\\Program Files\\Windows Defender\\MsMpEng.exe"))))
