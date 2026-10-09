// Title: AddinUtil.EXE Execution From Uncommon Directory
// ID: 6120ac2a-a34b-42c0-a9bd-1fb9f459f348
// Status: test
// Level: medium
// Author: Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
// Date: 2023-09-18
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) from a non-standard directory.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\addinutil.exe") OR (OriginalFileName == "AddInUtil.exe")) AND NOT (((Image contains ":\\Windows\\Microsoft.NET\\Framework\\" OR Image contains ":\\Windows\\Microsoft.NET\\Framework64\\" OR Image contains ":\\Windows\\Microsoft.NET\\FrameworkArm\\" OR Image contains ":\\Windows\\Microsoft.NET\\FrameworkArm64\\" OR Image contains ":\\Windows\\WinSxS\\"))))
