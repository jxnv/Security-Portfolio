-- Title: Suspicious Get-ADReplAccount
-- ID: 060c3ef1-fd0a-4091-bf46-e7d625f60b73
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-02-06
-- Tags: attack.credential-access, attack.t1003.006
-- Description: The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory.
-- These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ScriptBlockText ILIKE '%Get-ADReplAccount%' AND ScriptBlockText ILIKE '%-All %' AND ScriptBlockText ILIKE '%-Server %'))
