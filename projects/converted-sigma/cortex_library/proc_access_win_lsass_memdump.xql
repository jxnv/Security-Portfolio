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

dataset = xdr_data | filter ((TargetImage endswith "\\lsass.exe" and (GrantedAccess contains "0x1038" or GrantedAccess contains "0x1438" or GrantedAccess contains "0x143a" or GrantedAccess contains "0x1fffff") and (CallTrace contains "dbgcore.dll" or CallTrace contains "dbghelp.dll" or CallTrace contains "kernel32.dll" or CallTrace contains "kernelbase.dll" or CallTrace contains "ntdll.dll")) and not (((SourceUser contains "AUTHORI" or SourceUser contains "AUTORI"))) and not ((((SourceImage endswith ":\\Windows\\Sysmon64.exe" or SourceImage endswith ":\\Windows\\Sysmon64a.exe")) or ((CallTrace contains ":\\Windows\\Temp\\asgard2-agent\\" and CallTrace contains "\\thor\\thor64.exe+" and CallTrace contains "|UNKNOWN(") and GrantedAccess = "0x103800"))))
