-- Title: PowerShell Web Access Feature Enabled Via DISM
-- ID: 7e8f2d3b-9c1a-4f67-b9e8-8d9006e0e51f
-- Status: test
-- Level: high
-- Author: Michael Haag
-- Date: 2024-09-03
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1548.002
-- Description: Detects the use of DISM to enable the PowerShell Web Access feature, which could be used for remote access and potential abuse
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%WindowsPowerShellWebAccess%' AND CommandLine ILIKE '%/online%' AND CommandLine ILIKE '%/enable-feature%')) AND ((Image ILIKE '%\\dism.exe') OR (OriginalFileName = 'DISM.EXE')))
