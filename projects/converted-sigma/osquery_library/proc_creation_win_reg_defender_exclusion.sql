-- Title: Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE
-- ID: 48917adc-a28e-4f5d-b729-11e75da8941f
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-02-13
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the usage of "reg.exe" to add Defender folder exclusions. Qbot has been seen using this technique to add exclusions for folders within AppData and ProgramData.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*\\reg.exe" AND (CommandLine LIKE '%SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths%' OR CommandLine LIKE '%SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths%') AND (CommandLine LIKE '%ADD %' AND CommandLine LIKE '%/t %' AND CommandLine LIKE '%REG_DWORD %' AND CommandLine LIKE '%/v %' AND CommandLine LIKE '%/d %' AND CommandLine LIKE '%0%'))
