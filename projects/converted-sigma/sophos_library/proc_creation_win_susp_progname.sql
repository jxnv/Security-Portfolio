-- Title: Suspicious Program Names
-- ID: efdd8dd5-cee8-4e59-9390-7d4d5e4dd6f6
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-11
-- Tags: attack.execution, attack.t1059
-- Description: Detects suspicious patterns in program names or folders that are often found in malicious samples or hacktools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%inject.ps1%' OR CommandLine ILIKE '%Invoke-CVE%' OR CommandLine ILIKE '%pupy.ps1%' OR CommandLine ILIKE '%payload.ps1%' OR CommandLine ILIKE '%beacon.ps1%' OR CommandLine ILIKE '%PowerView.ps1%' OR CommandLine ILIKE '%bypass.ps1%' OR CommandLine ILIKE '%obfuscated.ps1%' OR CommandLine ILIKE '%obfusc.ps1%' OR CommandLine ILIKE '%obfus.ps1%' OR CommandLine ILIKE '%obfs.ps1%' OR CommandLine ILIKE '%evil.ps1%' OR CommandLine ILIKE '%MiniDogz.ps1%' OR CommandLine ILIKE '%_enc.ps1%' OR CommandLine ILIKE '%\\shell.ps1%' OR CommandLine ILIKE '%\\rshell.ps1%' OR CommandLine ILIKE '%revshell.ps1%' OR CommandLine ILIKE '%\\av.ps1%' OR CommandLine ILIKE '%\\av_test.ps1%' OR CommandLine ILIKE '%adrecon.ps1%' OR CommandLine ILIKE '%mimikatz.ps1%' OR CommandLine ILIKE '%\\PowerUp_%' OR CommandLine ILIKE '%powerup.ps1%' OR CommandLine ILIKE '%\\Temp\\a.ps1%' OR CommandLine ILIKE '%\\Temp\\p.ps1%' OR CommandLine ILIKE '%\\Temp\\1.ps1%' OR CommandLine ILIKE '%Hound.ps1%' OR CommandLine ILIKE '%encode.ps1%' OR CommandLine ILIKE '%powercat.ps1%')) OR (((Image ILIKE '%\\CVE-202%' OR Image ILIKE '%\\CVE202%')) OR ((Image ILIKE '%\\poc.exe' OR Image ILIKE '%\\artifact.exe' OR Image ILIKE '%\\artifact64.exe' OR Image ILIKE '%\\artifact_protected.exe' OR Image ILIKE '%\\artifact32.exe' OR Image ILIKE '%\\artifact32big.exe' OR Image ILIKE '%obfuscated.exe' OR Image ILIKE '%obfusc.exe' OR Image ILIKE '%\\meterpreter'))))
