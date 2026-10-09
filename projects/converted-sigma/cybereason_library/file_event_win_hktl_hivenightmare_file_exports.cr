// Title: HackTool - Typical HiveNightmare SAM File Export
// ID: 6ea858a8-ba71-4a12-b2cc-5d83312404c7
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-07-23
// Tags: attack.credential-access, attack.t1552.001, cve.2021-36934
// Description: Detects files written by the different tools that exploit HiveNightmare
// Converted by: Sigma Universal SIEM/EDR CLI

(((TargetFilename contains "\\hive_sam_" OR TargetFilename contains "\\SAM-2021-" OR TargetFilename contains "\\SAM-2022-" OR TargetFilename contains "\\SAM-2023-" OR TargetFilename contains "\\SAM-haxx" OR TargetFilename contains "\\Sam.save")) OR (TargetFilename == "C:\\windows\\temp\\sam"))
