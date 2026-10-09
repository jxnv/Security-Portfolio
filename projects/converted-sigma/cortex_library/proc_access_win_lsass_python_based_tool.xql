// Title: Credential Dumping Activity By Python Based Tool
// ID: f8be3e82-46a3-4e4e-ada5-8e538ae8b9c9
// Status: stable
// Level: high
// Author: Bhabesh Raj, Jonhnathan Ribeiro
// Date: 2023-11-27
// Tags: attack.credential-access, attack.t1003.001, attack.s0349
// Description: Detects LSASS process access for potential credential dumping by a Python-like tool such as LaZagne or Pypykatz.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetImage endswith "\\lsass.exe" and (CallTrace contains "_ctypes.pyd+" and CallTrace contains ":\\Windows\\System32\\KERNELBASE.dll+" and CallTrace contains ":\\Windows\\SYSTEM32\\ntdll.dll+") and (CallTrace contains "python27.dll+" or CallTrace contains "python3*.dll+") and GrantedAccess = "0x1FFFFF")
