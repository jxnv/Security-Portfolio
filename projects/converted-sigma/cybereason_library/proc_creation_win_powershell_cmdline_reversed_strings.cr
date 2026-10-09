// Title: Potential PowerShell Obfuscation Via Reversed Commands
// ID: b6b49cd1-34d6-4ead-b1bf-176e9edba9a4
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton
// Date: 2020-10-11
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects the presence of reversed PowerShell commands in the CommandLine. This is often used as a method of obfuscation by attackers
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine contains "hctac" OR CommandLine contains "kaerb" OR CommandLine contains "dnammoc" OR CommandLine contains "ekovn" OR CommandLine contains "eliFd" OR CommandLine contains "rahc" OR CommandLine contains "etirw" OR CommandLine contains "golon" OR CommandLine contains "tninon" OR CommandLine contains "eddih" OR CommandLine contains "tpircS" OR CommandLine contains "ssecorp" OR CommandLine contains "llehsrewop" OR CommandLine contains "esnopser" OR CommandLine contains "daolnwod" OR CommandLine contains "tneilCbeW" OR CommandLine contains "tneilc" OR CommandLine contains "ptth" OR CommandLine contains "elifotevas" OR CommandLine contains "46esab" OR CommandLine contains "htaPpmeTteG" OR CommandLine contains "tcejbO" OR CommandLine contains "maerts" OR CommandLine contains "hcaerof" OR CommandLine contains "retupmoc")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName == "PowerShell.EXE" OR OriginalFileName == "pwsh.dll")))) AND NOT (((CommandLine contains " -EncodedCommand " OR CommandLine contains " -enc "))))
