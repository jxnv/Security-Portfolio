// Title: Add New Download Source To Winget
// ID: 05ebafc8-7aa2-4bcd-a269-2aec93f9e842
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-17
// Tags: attack.execution, attack.t1059
// Description: Detects usage of winget to add new additional download sources
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*source *" AND CommandLine: "*add *")) AND ((Image="*\\winget.exe") OR (OriginalFileName: "winget.exe")))
