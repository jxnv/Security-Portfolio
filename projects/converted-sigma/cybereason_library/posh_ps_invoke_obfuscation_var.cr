// Title: Invoke-Obfuscation VAR+ Launcher - PowerShell
// ID: 0adfbc14-0ed1-11eb-adc1-0242ac120002
// Status: test
// Level: high
// Author: Jonathan Cheong, oscd.community
// Date: 2020-10-15
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated use of Environment Variables to execute PowerShell
// Converted by: Sigma Universal SIEM/EDR CLI

(ScriptBlockText=regex("cmd.{0,5}(?:/c|/r)(?:\\s|)\"set\\s[a-zA-Z]{3,6}.*(?:\\{\\d\\}){1,}\\\\\"\\s+?-f(?:.*\\)){1,}.*\""))
