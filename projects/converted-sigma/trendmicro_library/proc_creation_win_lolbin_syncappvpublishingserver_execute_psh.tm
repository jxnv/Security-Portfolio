// Title: SyncAppvPublishingServer Execute Arbitrary PowerShell Code
// ID: fbd7c32d-db2a-4418-b92c-566eb8911133
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-07-12
// Tags: attack.stealth, attack.t1218
// Description: Executes arbitrary PowerShell code using SyncAppvPublishingServer.exe.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "*\"n; *") AND ((Image="*\\SyncAppvPublishingServer.exe") OR (OriginalFileName: "syncappvpublishingserver.exe")))
