// Title: IIS Native-Code Module Command Line Installation
// ID: 9465ddf4-f9e4-4ebd-8d98-702df3a93239
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2019-12-11
// Tags: attack.persistence, attack.t1505.003
// Description: Detects suspicious IIS native-code module installations via command line
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine contains "install" AND CommandLine contains "module") AND (CommandLine contains "-name:" OR CommandLine contains "/name:")) AND ((Image="*\\appcmd.exe") OR (OriginalFileName == "appcmd.exe"))) AND NOT ((ParentImage == "C:\\Windows\\System32\\inetsrv\\iissetup.exe")))
