// Title: Hidden Powershell in Link File Pattern
// ID: 30e92f50-bb5a-4884-98b5-d20aa80f3d7a
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-02-06
// Tags: attack.execution, attack.t1059.001
// Description: Detects events that appear when a user click on a link file with a powershell command in it
// Converted by: Sigma Universal SIEM/EDR CLI

(ParentImage == "C:\\Windows\\explorer.exe" AND Image == "C:\\Windows\\System32\\cmd.exe" AND (CommandLine contains "powershell" AND CommandLine contains ".lnk"))
