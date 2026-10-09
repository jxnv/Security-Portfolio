// Title: Remote LSASS Process Access Through Windows Remote Management
// ID: aa35a627-33fb-4d04-a165-d33b4afca3e8
// Status: stable
// Level: high
// Author: Patryk Prauze - ING Tech
// Date: 2019-05-20
// Tags: attack.credential-access, attack.execution, attack.t1003.001, attack.t1059.001, attack.lateral-movement, attack.t1021.006, attack.s0002
// Description: Detects remote access to the LSASS process via WinRM. This could be a sign of credential dumping from tools like mimikatz.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetImage="*\\lsass.exe" AND SourceImage="*:\\Windows\\system32\\wsmprovhost.exe") AND NOT ((GrantedAccess == "0x80000000")))
