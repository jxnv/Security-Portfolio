// Title: VeeamBackup Database Credentials Dump Via Sqlcmd.EXE
// ID: b57ba453-b384-4ab9-9f40-1038086b4e53
// Status: test
// Level: high
// Author: frack113
// Date: 2021-12-20
// Tags: attack.collection, attack.t1005
// Description: Detects dump of credentials in VeeamBackup dbo
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*SELECT*" AND CommandLine: "*TOP*" AND CommandLine: "*[VeeamBackup].[dbo].[Credentials]*")) AND (Image="*\\sqlcmd.exe"))
