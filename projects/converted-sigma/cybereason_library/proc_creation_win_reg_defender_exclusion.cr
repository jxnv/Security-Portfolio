// Title: Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE
// ID: 48917adc-a28e-4f5d-b729-11e75da8941f
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-02-13
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the usage of "reg.exe" to add Defender folder exclusions. Qbot has been seen using this technique to add exclusions for folders within AppData and ProgramData.
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*\\reg.exe" AND (CommandLine contains "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" OR CommandLine contains "SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths") AND (CommandLine contains "ADD " AND CommandLine contains "/t " AND CommandLine contains "REG_DWORD " AND CommandLine contains "/v " AND CommandLine contains "/d " AND CommandLine contains "0"))
