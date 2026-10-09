-- Title: VeeamBackup Database Credentials Dump Via Sqlcmd.EXE
-- ID: b57ba453-b384-4ab9-9f40-1038086b4e53
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2021-12-20
-- Tags: attack.collection, attack.t1005
-- Description: Detects dump of credentials in VeeamBackup dbo
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%SELECT%' AND CommandLine LIKE '%TOP%' AND CommandLine LIKE '%[VeeamBackup].[dbo].[Credentials]%')) AND (Image="*\\sqlcmd.exe"))
