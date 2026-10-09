// Title: WinRAR Execution in Non-Standard Folder
// ID: 4ede543c-e098-43d9-a28f-dd784a13132f
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Tigzy
// Date: 2021-11-17
// Tags: attack.collection, attack.t1560.001
// Description: Detects a suspicious WinRAR execution in a folder which is not the default installation folder
// Converted by: Sigma Universal SIEM/EDR CLI

((((Image="*\\rar.exe" OR Image="*\\winrar.exe")) OR ((Description: "Command line RAR" OR Description: "WinRAR"))) AND NOT ((((Image: "*:\\Program Files (x86)\\WinRAR\\*" OR Image: "*:\\Program Files\\WinRAR\\*")) OR (Image="*\\UnRAR.exe"))) AND NOT ((Image: "*:\\Windows\\Temp\\*")))
