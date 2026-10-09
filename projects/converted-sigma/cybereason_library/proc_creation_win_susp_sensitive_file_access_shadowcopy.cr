// Title: Sensitive File Access Via Volume Shadow Copy Backup
// ID: f57f8d16-1f39-4dcb-a604-6c73d9b54b3d
// Status: test
// Level: high
// Author: Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems)
// Date: 2021-08-09
// Tags: attack.impact, attack.t1490
// Description: Detects a command that accesses the VolumeShadowCopy in order to extract sensitive files such as the Security or SAM registry hives or the AD database (ntds.dit)
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "\\\\\\\\\\?\\\\GLOBALROOT\\\\Device\\\\HarddiskVolumeShadowCopy") AND ((CommandLine contains "\\\\NTDS.dit" OR CommandLine contains "\\\\SYSTEM" OR CommandLine contains "\\\\SECURITY")))
