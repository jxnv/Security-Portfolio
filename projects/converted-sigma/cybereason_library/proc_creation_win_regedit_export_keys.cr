// Title: Exports Registry Key To a File
// ID: f0e53e89-8d22-46ea-9db5-9d4796ee2f8a
// Status: test
// Level: low
// Author: Oddvar Moe, Sander Wiebing, oscd.community
// Date: 2020-10-07
// Tags: attack.exfiltration, attack.discovery, attack.t1012
// Description: Detects the export of the target Registry key to a file.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " -E ") AND ((Image="*\\regedit.exe") OR (OriginalFileName == "REGEDIT.EXE"))) AND NOT ((((CommandLine contains "hklm" OR CommandLine contains "hkey_local_machine")) AND ((CommandLine="*\\system" OR CommandLine="*\\sam" OR CommandLine="*\\security")))))
