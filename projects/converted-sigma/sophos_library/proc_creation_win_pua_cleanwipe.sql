-- Title: PUA - CleanWipe Execution
-- ID: f44800ac-38ec-471f-936e-3fa7d9c53100
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-12-18
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\SepRemovalToolNative_x64.exe') OR (Image ILIKE '%\\CATClean.exe' AND CommandLine ILIKE '%--uninstall%') OR (Image ILIKE '%\\NetInstaller.exe' AND CommandLine ILIKE '%-r%') OR (Image ILIKE '%\\WFPUnins.exe' AND (CommandLine ILIKE '%/uninstall%' AND CommandLine ILIKE '%/enterprise%')))
