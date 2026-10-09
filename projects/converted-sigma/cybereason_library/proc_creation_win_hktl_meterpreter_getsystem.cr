// Title: Potential Meterpreter/CobaltStrike Activity
// ID: 15619216-e993-4721-b590-4c520615a67d
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov, Ecco, Florian Roth
// Date: 2019-10-26
// Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.002
// Description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\services.exe") AND (((CommandLine contains "/c" AND CommandLine contains "echo" AND CommandLine contains "\\pipe\\") AND (CommandLine contains "cmd" OR CommandLine contains "%COMSPEC%")) OR ((CommandLine contains "rundll32" AND CommandLine contains ".dll,a" AND CommandLine contains "/p:"))) AND NOT ((CommandLine contains "MpCmdRun")))
