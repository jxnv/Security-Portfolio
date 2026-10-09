-- Title: Suspicious Reg Add BitLocker
-- ID: 0e0255bf-2548-47b8-9582-c0955c9283f5
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2021-11-15
-- Tags: attack.impact, attack.t1486
-- Description: Detects suspicious addition to BitLocker related registry keys via the reg.exe utility
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%REG%' AND CommandLine LIKE '%ADD%' AND CommandLine LIKE '%\\SOFTWARE\\Policies\\Microsoft\\FVE%' AND CommandLine LIKE '%/v%' AND CommandLine LIKE '%/f%') AND (CommandLine LIKE '%EnableBDEWithNoTPM%' OR CommandLine LIKE '%UseAdvancedStartup%' OR CommandLine LIKE '%UseTPM%' OR CommandLine LIKE '%UseTPMKey%' OR CommandLine LIKE '%UseTPMKeyPIN%' OR CommandLine LIKE '%RecoveryKeyMessageSource%' OR CommandLine LIKE '%UseTPMPIN%' OR CommandLine LIKE '%RecoveryKeyMessage%'))
