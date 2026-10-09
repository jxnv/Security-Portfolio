// Title: Use Short Name Path in Image
// ID: a96970af-f126-420d-90e1-d37bf25e50e1
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali
// Date: 2022-08-07
// Tags: attack.stealth, attack.t1564.004
// Description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image detection
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image contains "~1\\" OR Image contains "~2\\")) AND NOT (((((Image contains "\\AppData\\" AND Image contains "\\Temp\\")) OR ((Image="*~1\\unzip.exe" OR Image="*~1\\7zG.exe"))) OR ((ParentImage == "C:\\Windows\\System32\\Dism.exe" OR ParentImage == "C:\\Windows\\System32\\cleanmgr.exe")))) AND NOT ((((Product == "InstallShield (R)") OR (Description == "InstallShield (R) Setup Engine") OR (Company == "InstallShield Software Corporation")) OR (ParentImage="*\\thor\\thor64.exe") OR (ParentImage="*\\WebEx\\WebexHost.exe"))))
