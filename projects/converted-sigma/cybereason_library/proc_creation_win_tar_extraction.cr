// Title: Compressed File Extraction Via Tar.EXE
// ID: bf361876-6620-407a-812f-bfe11e51e924
// Status: test
// Level: low
// Author: AdmU3
// Date: 2023-12-19
// Tags: attack.collection, attack.exfiltration, attack.t1560, attack.t1560.001
// Description: Detects execution of "tar.exe" in order to extract compressed file.
// Adversaries may abuse various utilities in order to decompress data to avoid detection.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "-x") AND ((Image="*\\tar.exe") OR (OriginalFileName == "bsdtar")))
