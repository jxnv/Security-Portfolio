// Title: Potential Credential Dumping Activity Via LSASS
// ID: 5ef9853e-4d0e-4a70-846f-a9ca37d876da
// Status: test
// Level: medium
// Author: Samir Bousseaden, Michael Haag
// Date: 2019-04-03
// Tags: attack.credential-access, attack.t1003.001, attack.s0002
// Description: Detects process access requests to the LSASS process with specific call trace calls and access masks.
// This behaviour is expressed by many credential dumping tools such as Mimikatz, NanoDump, Invoke-Mimikatz, Procdump and even the Taskmgr dumping feature.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetImage="*\\lsass.exe" AND (GrantedAccess: "*0x1038*" OR GrantedAccess: "*0x1438*" OR GrantedAccess: "*0x143a*" OR GrantedAccess: "*0x1fffff*") AND (CallTrace: "*dbgcore.dll*" OR CallTrace: "*dbghelp.dll*" OR CallTrace: "*kernel32.dll*" OR CallTrace: "*kernelbase.dll*" OR CallTrace: "*ntdll.dll*")) AND NOT (((SourceUser: "*AUTHORI*" OR SourceUser: "*AUTORI*"))) AND NOT ((((SourceImage="*:\\Windows\\Sysmon64.exe" OR SourceImage="*:\\Windows\\Sysmon64a.exe")) OR ((CallTrace: "*:\\Windows\\Temp\\asgard2-agent\\*" AND CallTrace: "*\\thor\\thor64.exe+*" AND CallTrace: "*|UNKNOWN(*") AND GrantedAccess: "0x103800"))))
