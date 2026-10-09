-- Title: PUA - Wsudo Suspicious Execution
-- ID: bdeeabc9-ff2a-4a51-be59-bb253aac7891
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-02
-- Tags: attack.execution, attack.privilege-escalation, attack.t1059
-- Description: Detects usage of wsudo (Windows Sudo Utility). Which is a tool that let the user execute programs with different permissions (System, Trusted Installer, Administrator...etc)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%-u System%' OR CommandLine ILIKE '%-uSystem%' OR CommandLine ILIKE '%-u TrustedInstaller%' OR CommandLine ILIKE '%-uTrustedInstaller%' OR CommandLine ILIKE '% --ti %')) OR ((Image ILIKE '%\\wsudo.exe') OR (OriginalFileName = 'wsudo.exe') OR (Description = 'Windows sudo utility') OR (ParentImage ILIKE '%\\wsudo-bridge.exe')))
