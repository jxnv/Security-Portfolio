// Title: Forfiles.EXE Child Process Masquerading
// ID: f53714ec-5077-420e-ad20-907ff9bb2958
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Anish Bogati
// Date: 2024-01-05
// Tags: attack.stealth, attack.t1036
// Description: Detects the execution of "forfiles" from a non-default location, in order to potentially spawn a custom "cmd.exe" from the current working directory.
// Converted by: Sigma Universal SIEM/EDR CLI

(((ParentCommandLine="*.exe" OR ParentCommandLine="*.exe\"") AND Image="*\\cmd.exe" AND CommandLine="/c echo \"*") AND NOT (((ParentImage contains ":\\Windows\\System32\\" OR ParentImage contains ":\\Windows\\SysWOW64\\") AND ParentImage="*\\forfiles.exe" AND (Image contains ":\\Windows\\System32\\" OR Image contains ":\\Windows\\SysWOW64\\") AND Image="*\\cmd.exe")))
