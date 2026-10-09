// Title: Uncommon Service Installation Image Path
// ID: 26481afe-db26-4228-b264-25a29fe6efc7
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-18
// Tags: attack.persistence, attack.privilege-escalation, car.2013-09-005, attack.t1543.003
// Description: Detects uncommon service installation commands by looking at suspicious or uncommon image path values containing references to encoded powershell commands, temporary paths, etc.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Provider_Name = "Service Control Manager" and EventID = 7045) and (((ImagePath contains "\\\\\\\\.\\\\pipe" or ImagePath contains "\\Users\\Public\\" or ImagePath contains "\\Windows\\Temp\\")) or ((ImagePath contains " -e") and ((ImagePath contains " aQBlAHgA" or ImagePath contains " aWV4I" or ImagePath contains " IAB" or ImagePath contains " JAB" or ImagePath contains " PAA" or ImagePath contains " SQBFAFgA" or ImagePath contains " SUVYI")))) and not ((ImagePath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\")) and not ((ImagePath startswith "C:\\WINDOWS\\TEMP\\thor10-remote\\thor64.exe")))
