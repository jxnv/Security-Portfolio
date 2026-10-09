// Title: Add Potential Suspicious New Download Source To Winget
// ID: c15a46a0-07d4-4c87-b4b6-89207835a83b
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-17
// Tags: attack.execution, attack.t1059
// Description: Detects usage of winget to add new potentially suspicious download sources
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*source *" AND CommandLine: "*add *")) AND ((Image="*\\winget.exe") OR (OriginalFileName: "winget.exe")) AND (CommandLine=regex("://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")))
