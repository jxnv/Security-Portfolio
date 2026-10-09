-- Title: PUA - Wsudo Suspicious Execution
-- ID: bdeeabc9-ff2a-4a51-be59-bb253aac7891
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-02
-- Tags: attack.execution, attack.privilege-escalation, attack.t1059
-- Description: Detects usage of wsudo (Windows Sudo Utility). Which is a tool that let the user execute programs with different permissions (System, Trusted Installer, Administrator...etc)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%-u System%' OR CommandLine LIKE '%-uSystem%' OR CommandLine LIKE '%-u TrustedInstaller%' OR CommandLine LIKE '%-uTrustedInstaller%' OR CommandLine LIKE '% --ti %')) OR ((Image="*\\wsudo.exe") OR (OriginalFileName = 'wsudo.exe') OR (Description = 'Windows sudo utility') OR (ParentImage="*\\wsudo-bridge.exe")))
