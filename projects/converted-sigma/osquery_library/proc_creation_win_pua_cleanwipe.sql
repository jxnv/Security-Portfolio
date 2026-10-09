-- Title: PUA - CleanWipe Execution
-- ID: f44800ac-38ec-471f-936e-3fa7d9c53100
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-12-18
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\SepRemovalToolNative_x64.exe") OR (Image="*\\CATClean.exe" AND CommandLine LIKE '%--uninstall%') OR (Image="*\\NetInstaller.exe" AND CommandLine LIKE '%-r%') OR (Image="*\\WFPUnins.exe" AND (CommandLine LIKE '%/uninstall%' AND CommandLine LIKE '%/enterprise%')))
