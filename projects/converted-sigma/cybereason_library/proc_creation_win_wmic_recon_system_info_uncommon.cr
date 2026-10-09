// Title: Uncommon System Information Discovery Via Wmic.EXE
// ID: 9d5a1274-922a-49d0-87f3-8c653483b909
// Status: test
// Level: medium
// Author: TropChaud
// Date: 2023-01-26
// Tags: attack.discovery, attack.t1082
// Description: Detects the use of the WMI command-line (WMIC) utility to identify and display various system information,
// including OS, CPU, GPU, and disk drive names; memory capacity; display resolution; and baseboard, BIOS,
// and GPU driver products/versions.
// Some of these commands were used by Aurora Stealer in late 2022/early 2023.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "LOGICALDISK get Name,Size,FreeSpace" OR CommandLine contains "os get Caption,OSArchitecture,Version")) AND ((Description == "WMI Commandline Utility") OR (OriginalFileName == "wmic.exe") OR (Image="*\\WMIC.exe")))
