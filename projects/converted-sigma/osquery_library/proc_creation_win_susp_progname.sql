-- Title: Suspicious Program Names
-- ID: efdd8dd5-cee8-4e59-9390-7d4d5e4dd6f6
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-11
-- Tags: attack.execution, attack.t1059
-- Description: Detects suspicious patterns in program names or folders that are often found in malicious samples or hacktools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%inject.ps1%' OR CommandLine LIKE '%Invoke-CVE%' OR CommandLine LIKE '%pupy.ps1%' OR CommandLine LIKE '%payload.ps1%' OR CommandLine LIKE '%beacon.ps1%' OR CommandLine LIKE '%PowerView.ps1%' OR CommandLine LIKE '%bypass.ps1%' OR CommandLine LIKE '%obfuscated.ps1%' OR CommandLine LIKE '%obfusc.ps1%' OR CommandLine LIKE '%obfus.ps1%' OR CommandLine LIKE '%obfs.ps1%' OR CommandLine LIKE '%evil.ps1%' OR CommandLine LIKE '%MiniDogz.ps1%' OR CommandLine LIKE '%_enc.ps1%' OR CommandLine LIKE '%\\shell.ps1%' OR CommandLine LIKE '%\\rshell.ps1%' OR CommandLine LIKE '%revshell.ps1%' OR CommandLine LIKE '%\\av.ps1%' OR CommandLine LIKE '%\\av_test.ps1%' OR CommandLine LIKE '%adrecon.ps1%' OR CommandLine LIKE '%mimikatz.ps1%' OR CommandLine LIKE '%\\PowerUp_%' OR CommandLine LIKE '%powerup.ps1%' OR CommandLine LIKE '%\\Temp\\a.ps1%' OR CommandLine LIKE '%\\Temp\\p.ps1%' OR CommandLine LIKE '%\\Temp\\1.ps1%' OR CommandLine LIKE '%Hound.ps1%' OR CommandLine LIKE '%encode.ps1%' OR CommandLine LIKE '%powercat.ps1%')) OR (((Image LIKE '%\\CVE-202%' OR Image LIKE '%\\CVE202%')) OR ((Image="*\\poc.exe" OR Image="*\\artifact.exe" OR Image="*\\artifact64.exe" OR Image="*\\artifact_protected.exe" OR Image="*\\artifact32.exe" OR Image="*\\artifact32big.exe" OR Image="*obfuscated.exe" OR Image="*obfusc.exe" OR Image="*\\meterpreter"))))
