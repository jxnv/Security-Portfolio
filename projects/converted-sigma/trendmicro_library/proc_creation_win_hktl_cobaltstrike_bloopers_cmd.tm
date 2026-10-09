// Title: Operator Bloopers Cobalt Strike Commands
// ID: 647c7b9e-d784-4fda-b9a0-45c565a7b729
// Status: test
// Level: high
// Author: _pete_0, TheDFIRReport
// Date: 2022-05-06
// Tags: attack.execution, attack.t1059.003, stp.1u
// Description: Detects use of Cobalt Strike commands accidentally entered in the CMD shell
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine="cmd *" OR CommandLine="cmd.exe*" OR CommandLine="c:\\windows\\system32\\cmd.exe*") AND (CommandLine: "*psinject*" OR CommandLine: "*spawnas*" OR CommandLine: "*make_token*" OR CommandLine: "*remote-exec*" OR CommandLine: "*rev2self*" OR CommandLine: "*dcsync*" OR CommandLine: "*logonpasswords*" OR CommandLine: "*execute-assembly*" OR CommandLine: "*getsystem*")) AND ((OriginalFileName: "Cmd.Exe") OR (Image="*\\cmd.exe")))
