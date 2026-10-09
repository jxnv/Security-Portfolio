// Title: Operator Bloopers Cobalt Strike Modules
// ID: 4f154fb6-27d1-4813-a759-78b93e0b9c48
// Status: test
// Level: high
// Author: _pete_0, TheDFIRReport
// Date: 2022-05-06
// Tags: attack.execution, attack.t1059.003
// Description: Detects Cobalt Strike module/commands accidentally entered in CMD shell
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*Invoke-UserHunter*" OR CommandLine: "*Invoke-ShareFinder*" OR CommandLine: "*Invoke-Kerberoast*" OR CommandLine: "*Invoke-SMBAutoBrute*" OR CommandLine: "*Invoke-Nightmare*" OR CommandLine: "*zerologon*" OR CommandLine: "*av_query*")) AND ((OriginalFileName: "Cmd.Exe") OR (Image="*\\cmd.exe")))
