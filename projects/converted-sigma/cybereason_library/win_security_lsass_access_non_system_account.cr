// Title: LSASS Access From Non System Account
// ID: 962fe167-e48d-4fd6-9974-11e5b9a5d6d1
// Status: test
// Level: medium
// Author: Roberto Rodriguez @Cyb3rWard0g
// Date: 2019-06-20
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects potential mimikatz-like tools accessing LSASS from non system account
// Converted by: Sigma Universal SIEM/EDR CLI

(((EventID == "4663" OR EventID == "4656") AND (AccessMask == "0x100000" OR AccessMask == "0x1010" OR AccessMask == "0x1400" OR AccessMask == "0x1410" OR AccessMask == "0x1418" OR AccessMask == "0x1438" OR AccessMask == "0x143a" OR AccessMask == "0x1f0fff" OR AccessMask == "0x1f1fff" OR AccessMask == "0x1f2fff" OR AccessMask == "0x1f3fff" OR AccessMask == "0x40" OR AccessMask == "143a" OR AccessMask == "1f0fff" OR AccessMask == "1f1fff" OR AccessMask == "1f2fff" OR AccessMask == "1f3fff") AND ObjectType == "Process" AND ObjectName="*\\lsass.exe") AND NOT ((((ProcessName contains ":\\Program Files\\" OR ProcessName contains ":\\Program Files (x86)\\")) OR (SubjectUserName="*$") OR (ProcessName == "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" AND AccessMask == "0x1410"))) AND NOT ((ProcessName contains "\\SteamLibrary\\steamapps\\")))
