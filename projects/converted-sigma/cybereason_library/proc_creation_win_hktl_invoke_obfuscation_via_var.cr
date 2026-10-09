// Title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION
// ID: e9f55347-2928-4c06-88e5-1a7f8169942e
// Status: test
// Level: high
// Author: Timur Zinniatullin, oscd.community
// Date: 2020-10-13
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via VAR++ LAUNCHER
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "&&set" AND CommandLine contains "cmd" AND CommandLine contains "/c" AND CommandLine contains "-f") AND (CommandLine contains "{0}" OR CommandLine contains "{1}" OR CommandLine contains "{2}" OR CommandLine contains "{3}" OR CommandLine contains "{4}" OR CommandLine contains "{5}"))
