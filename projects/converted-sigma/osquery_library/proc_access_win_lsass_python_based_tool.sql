-- Title: Credential Dumping Activity By Python Based Tool
-- ID: f8be3e82-46a3-4e4e-ada5-8e538ae8b9c9
-- Status: stable
-- Level: high
-- Author: Bhabesh Raj, Jonhnathan Ribeiro
-- Date: 2023-11-27
-- Tags: attack.credential-access, attack.t1003.001, attack.s0349
-- Description: Detects LSASS process access for potential credential dumping by a Python-like tool such as LaZagne or Pypykatz.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (TargetImage="*\\lsass.exe" AND (CallTrace LIKE '%_ctypes.pyd+%' AND CallTrace LIKE '%:\\Windows\\System32\\KERNELBASE.dll+%' AND CallTrace LIKE '%:\\Windows\\SYSTEM32\\ntdll.dll+%') AND (CallTrace LIKE '%python27.dll+%' OR CallTrace LIKE '%python3*.dll+%') AND GrantedAccess = '0x1FFFFF')
