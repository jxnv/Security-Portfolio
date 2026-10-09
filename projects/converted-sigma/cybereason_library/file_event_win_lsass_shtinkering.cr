// Title: LSASS Process Dump Artefact In CrashDumps Folder
// ID: 6902955a-01b7-432c-b32a-6f5f81d8f625
// Status: test
// Level: high
// Author: @pbssubhash
// Date: 2022-12-08
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects the presence of an LSASS dump file in the "CrashDumps" folder. This could be a sign of LSASS credential dumping. Techniques such as the LSASS Shtinkering have been seen abusing the Windows Error Reporting to dump said process.
// Converted by: Sigma Universal SIEM/EDR CLI

(TargetFilename="C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\*" AND TargetFilename contains "lsass.exe." AND TargetFilename="*.dmp")
