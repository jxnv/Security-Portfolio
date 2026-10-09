// Title: Operator Bloopers Cobalt Strike Commands
// ID: 647c7b9e-d784-4fda-b9a0-45c565a7b729
// Status: test
// Level: high
// Author: _pete_0, TheDFIRReport
// Date: 2022-05-06
// Tags: attack.execution, attack.t1059.003, stp.1u
// Description: Detects use of Cobalt Strike commands accidentally entered in the CMD shell
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine="cmd *" OR CommandLine="cmd.exe*" OR CommandLine="c:\\windows\\system32\\cmd.exe*") AND (CommandLine contains "psinject" OR CommandLine contains "spawnas" OR CommandLine contains "make_token" OR CommandLine contains "remote-exec" OR CommandLine contains "rev2self" OR CommandLine contains "dcsync" OR CommandLine contains "logonpasswords" OR CommandLine contains "execute-assembly" OR CommandLine contains "getsystem")) AND ((OriginalFileName == "Cmd.Exe") OR (Image="*\\cmd.exe")))
