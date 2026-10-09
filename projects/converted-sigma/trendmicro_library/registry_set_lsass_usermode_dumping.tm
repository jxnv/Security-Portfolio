// Title: Lsass Full Dump Request Via DumpType Registry Settings
// ID: 33efc23c-6ea2-4503-8cfe-bdf82ce8f719
// Status: test
// Level: high
// Author: @pbssubhash
// Date: 2022-12-08
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects the setting of the "DumpType" registry value to "2" which stands for a "Full Dump". Technique such as LSASS Shtinkering requires this value to be "2" in order to dump LSASS.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject: "*\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType*" OR TargetObject: "*\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\lsass.exe\\DumpType*") AND Details: "DWORD (0x00000002)")
