// Title: Security Service Disabled Via Reg.EXE
// ID: 5e95028c-5229-4214-afae-d653d573d0ec
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), John Lambert (idea), elhoim
// Date: 2021-07-14
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects execution of "reg.exe" to disable security services such as Windows Defender.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "d 4" AND CommandLine contains "v Start") AND (CommandLine contains "\\AppIDSvc" OR CommandLine contains "\\MsMpSvc" OR CommandLine contains "\\NisSrv" OR CommandLine contains "\\SecurityHealthService" OR CommandLine contains "\\Sense" OR CommandLine contains "\\UsoSvc" OR CommandLine contains "\\WdBoot" OR CommandLine contains "\\WdFilter" OR CommandLine contains "\\WdNisDrv" OR CommandLine contains "\\WdNisSvc" OR CommandLine contains "\\WinDefend" OR CommandLine contains "\\wscsvc" OR CommandLine contains "\\wuauserv")) AND ((CommandLine contains "reg" AND CommandLine contains "add")))
