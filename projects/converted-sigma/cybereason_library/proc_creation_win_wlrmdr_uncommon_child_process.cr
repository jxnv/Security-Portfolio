// Title: Wlrmdr.EXE Uncommon Argument Or Child Process
// ID: 9cfc00b6-bfb7-49ce-9781-ef78503154bb
// Status: experimental
// Level: medium
// Author: frack113, manasmbellani
// Date: 2022-02-16
// Tags: attack.stealth, attack.t1218
// Description: Detects the execution of "Wlrmdr.exe" with the "-u" command line flag which allows anything passed to it to be an argument of the ShellExecute API, which would allow an attacker to execute arbitrary binaries.
// This detection also focuses on any uncommon child processes spawned from "Wlrmdr.exe" as a supplement for those that posses "ParentImage" telemetry.
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\wlrmdr.exe") OR ((((CommandLine contains "-a " OR CommandLine contains "/a ")) AND ((CommandLine contains "-f " OR CommandLine contains "/f ")) AND ((CommandLine contains "-m " OR CommandLine contains "/m ")) AND ((CommandLine contains "-s " OR CommandLine contains "/s ")) AND ((CommandLine contains "-t " OR CommandLine contains "/t ")) AND ((CommandLine contains "-u " OR CommandLine contains "/u ")) AND ((Image="*\\wlrmdr.exe") OR (OriginalFileName == "WLRMNDR.EXE"))) AND NOT ((((ParentImage == "" OR ParentImage == "-")) OR (NOT ParentImage=*) OR (ParentImage == "C:\\Windows\\System32\\winlogon.exe")))))
