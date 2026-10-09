-- Title: HackTool - SecurityXploded Execution
-- ID: 7679d464-4f74-45e2-9e01-ac66c5eb041a
-- Status: stable
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2018-12-19
-- Tags: attack.credential-access, attack.t1555
-- Description: Detects the execution of SecurityXploded Tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Company = 'SecurityXploded') OR (Image ILIKE '%PasswordDump.exe') OR (OriginalFileName ILIKE '%PasswordDump.exe'))
