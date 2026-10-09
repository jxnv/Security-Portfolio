// Title: Potential Mpclient.DLL Sideloading Via Defender Binaries
// ID: 7002aa10-b8d4-47ae-b5ba-51ab07e228b9
// Status: test
// Level: high
// Author: Bhabesh Raj
// Date: 2022-08-01
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential sideloading of "mpclient.dll" by Windows Defender processes ("MpCmdRun" and "NisSrv") from their non-default directory.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\MpCmdRun.exe" OR Image="*\\NisSrv.exe")) AND NOT (((Image="C:\\Program Files (x86)\\Windows Defender\\*" OR Image="C:\\Program Files\\Microsoft Security Client\\*" OR Image="C:\\Program Files\\Windows Defender\\*" OR Image="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*" OR Image="C:\\Windows\\WinSxS\\*"))))
