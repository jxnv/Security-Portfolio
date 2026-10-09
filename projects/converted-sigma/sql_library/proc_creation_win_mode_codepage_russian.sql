-- Title: CodePage Modification Via MODE.COM To Russian Language
-- ID: 12fbff88-16b5-4b42-9754-cd001a789fb3
-- Status: test
-- Level: medium
-- Author: Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date: 2024-01-17
-- Tags: attack.stealth, attack.t1036
-- Description: Detects a CodePage modification using the "mode.com" utility to Russian language.
-- This behavior has been used by threat actors behind Dharma ransomware.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% con %' AND CommandLine ILIKE '% cp %' AND CommandLine ILIKE '% select=%') AND (CommandLine ILIKE '%=1251' OR CommandLine ILIKE '%=866')) AND ((Image ILIKE '%\\mode.com') OR (OriginalFileName = 'MODE.COM')))
