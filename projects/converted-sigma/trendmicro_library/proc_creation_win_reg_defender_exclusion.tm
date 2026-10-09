// Title: Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE
// ID: 48917adc-a28e-4f5d-b729-11e75da8941f
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-02-13
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the usage of "reg.exe" to add Defender folder exclusions. Qbot has been seen using this technique to add exclusions for folders within AppData and ProgramData.
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*\\reg.exe" AND (CommandLine: "*SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths*" OR CommandLine: "*SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths*") AND (CommandLine: "*ADD *" AND CommandLine: "*/t *" AND CommandLine: "*REG_DWORD *" AND CommandLine: "*/v *" AND CommandLine: "*/d *" AND CommandLine: "*0*"))
