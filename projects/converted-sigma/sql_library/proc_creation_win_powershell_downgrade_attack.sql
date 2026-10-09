-- Title: Potential PowerShell Downgrade Attack
-- ID: b3512211-c67e-4707-bedc-66efc7848863
-- Status: test
-- Level: medium
-- Author: Harish Segar (rule)
-- Date: 2020-03-20
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%\\powershell.exe' AND (CommandLine ILIKE '% -version 2 %' OR CommandLine ILIKE '% -versio 2 %' OR CommandLine ILIKE '% -versi 2 %' OR CommandLine ILIKE '% -vers 2 %' OR CommandLine ILIKE '% -ver 2 %' OR CommandLine ILIKE '% -ve 2 %' OR CommandLine ILIKE '% -v 2 %'))
