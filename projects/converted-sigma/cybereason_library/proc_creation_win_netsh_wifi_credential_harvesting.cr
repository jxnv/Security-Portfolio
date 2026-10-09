// Title: Harvesting Of Wifi Credentials Via Netsh.EXE
// ID: 42b1a5b8-353f-4f10-b256-39de4467faff
// Status: test
// Level: medium
// Author: Andreas Hunkeler (@Karneades), oscd.community
// Date: 2020-04-20
// Tags: attack.discovery, attack.credential-access, attack.t1040
// Description: Detect the harvesting of wifi credentials using netsh.exe
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "wlan" AND CommandLine contains " s" AND CommandLine contains " p" AND CommandLine contains " k" AND CommandLine contains "=clear")) AND ((Image="*\\netsh.exe") OR (OriginalFileName == "netsh.exe")))
