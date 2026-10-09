// Title: Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp
// ID: 551d9c1f-816c-445b-a7a6-7a3864720d60
// Status: test
// Level: high
// Author: Aaron Stratton
// Date: 2023-11-13
// Tags: attack.t1021.003, attack.lateral-movement
// Description: Detects suspicious child processes of Excel which could be an indicator of lateral movement leveraging the "ActivateMicrosoftApp" Excel DCOM object.
// Converted by: Sigma Universal SIEM/EDR CLI

((((OriginalFileName: "foxprow.exe" OR OriginalFileName: "schdplus.exe" OR OriginalFileName: "winproj.exe")) OR ((Image="*\\foxprow.exe" OR Image="*\\schdplus.exe" OR Image="*\\winproj.exe"))) AND (ParentImage="*\\excel.exe"))
