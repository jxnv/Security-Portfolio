// Title: Application Removed Via Wmic.EXE
// ID: b53317a0-8acf-4fd1-8de8-a5401e776b96
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-28
// Tags: attack.execution, attack.t1047
// Description: Detects the removal or uninstallation of an application via "Wmic.EXE".
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*call*" AND CommandLine: "*uninstall*")) AND ((Image="*\\WMIC.exe") OR (OriginalFileName: "wmic.exe")))
