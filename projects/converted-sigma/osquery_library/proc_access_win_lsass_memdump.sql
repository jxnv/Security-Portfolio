-- Title: Potential Credential Dumping Activity Via LSASS
-- ID: 5ef9853e-4d0e-4a70-846f-a9ca37d876da
-- Status: test
-- Level: medium
-- Author: Samir Bousseaden, Michael Haag
-- Date: 2019-04-03
-- Tags: attack.credential-access, attack.t1003.001, attack.s0002
-- Description: Detects process access requests to the LSASS process with specific call trace calls and access masks.
-- This behaviour is expressed by many credential dumping tools such as Mimikatz, NanoDump, Invoke-Mimikatz, Procdump and even the Taskmgr dumping feature.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((TargetImage="*\\lsass.exe" AND (GrantedAccess LIKE '%0x1038%' OR GrantedAccess LIKE '%0x1438%' OR GrantedAccess LIKE '%0x143a%' OR GrantedAccess LIKE '%0x1fffff%') AND (CallTrace LIKE '%dbgcore.dll%' OR CallTrace LIKE '%dbghelp.dll%' OR CallTrace LIKE '%kernel32.dll%' OR CallTrace LIKE '%kernelbase.dll%' OR CallTrace LIKE '%ntdll.dll%')) AND NOT (((SourceUser LIKE '%AUTHORI%' OR SourceUser LIKE '%AUTORI%'))) AND NOT ((((SourceImage="*:\\Windows\\Sysmon64.exe" OR SourceImage="*:\\Windows\\Sysmon64a.exe")) OR ((CallTrace LIKE '%:\\Windows\\Temp\\asgard2-agent\\%' AND CallTrace LIKE '%\\thor\\thor64.exe+%' AND CallTrace LIKE '%|UNKNOWN(%') AND GrantedAccess = '0x103800'))))
