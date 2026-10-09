// Title: PowerShell Download Via Net.WebClient - PowerShell Classic
// ID: 3236fcd0-b7e3-4433-b4f8-86ad61a9af2d
// Status: test
// Level: low
// Author: Florian Roth (Nextron Systems)
// Date: 2017-03-05
// Tags: attack.execution, attack.command-and-control, attack.t1059.001, attack.t1105
// Description: Detects PowerShell download activity, via the .DownloadFile() or .DownloadString() methods of the Net.WebClient class.
// This technique is often abused by attackers to download additional payloads.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Data: "*.DownloadFile(*" OR Data: "*.DownloadString(*")) AND (Data: "*Net.WebClient*"))
