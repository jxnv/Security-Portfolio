// Title: Potential Persistence Via Outlook Today Page
// ID: 487bb375-12ef-41f6-baae-c6a1572b4dd1
// Status: test
// Level: high
// Author: Tobias Michalski (Nextron Systems), David Bertho (@dbertho) & Eirik Sveen (@0xSV1), Storebrand
// Date: 2021-06-10
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects potential persistence activity via outlook today page.
// An attacker can set a custom page to execute arbitrary code and link to it via the registry values "URL" and "UserDefinedUrl".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "Software\\Microsoft\\Office\\" and TargetObject contains "\\Outlook\\Today\\")) and ((TargetObject endswith "\\Stamp" and Details = "DWORD (0x00000001)") or ((TargetObject endswith "\\URL" or TargetObject endswith "\\UserDefinedUrl"))) and not (((action_process_image_path startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" or action_process_image_path startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\Updates\\") and action_process_image_path endswith "\\OfficeClickToRun.exe")))
