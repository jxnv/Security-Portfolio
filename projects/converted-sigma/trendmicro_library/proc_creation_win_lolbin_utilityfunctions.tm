// Title: UtilityFunctions.ps1 Proxy Dll
// ID: 0403d67d-6227-4ea8-8145-4e72db7da120
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-05-28
// Tags: attack.stealth, attack.t1216
// Description: Detects the use of a Microsoft signed script executing a managed DLL with PowerShell.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "*UtilityFunctions.ps1*" OR CommandLine: "*RegSnapin *"))
