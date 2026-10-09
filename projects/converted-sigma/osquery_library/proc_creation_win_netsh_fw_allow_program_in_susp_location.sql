-- Title: Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE
-- ID: a35f5a72-f347-4e36-8895-9869b0d5fc6d
-- Status: test
-- Level: high
-- Author: Sander Wiebing, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
-- Date: 2020-05-25
-- Tags: attack.defense-impairment, attack.t1686.003
-- Description: Detects Netsh command execution that whitelists a program located in a suspicious location in the Windows Firewall
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%firewall%' AND CommandLine LIKE '%add%' AND CommandLine LIKE '%allowedprogram%')) OR ((CommandLine LIKE '%advfirewall%' AND CommandLine LIKE '%firewall%' AND CommandLine LIKE '%add%' AND CommandLine LIKE '%rule%' AND CommandLine LIKE '%action=allow%' AND CommandLine LIKE '%program=%'))) AND ((Image="*\\netsh.exe") OR (OriginalFileName = 'netsh.exe')) AND ((CommandLine LIKE '%:\\$Recycle.bin\\%' OR CommandLine LIKE '%:\\RECYCLER.BIN\\%' OR CommandLine LIKE '%:\\RECYCLERS.BIN\\%' OR CommandLine LIKE '%:\\SystemVolumeInformation\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Users\\Default\\%' OR CommandLine LIKE '%:\\Users\\Desktop\\%' OR CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\addins\\%' OR CommandLine LIKE '%:\\Windows\\cursors\\%' OR CommandLine LIKE '%:\\Windows\\debug\\%' OR CommandLine LIKE '%:\\Windows\\drivers\\%' OR CommandLine LIKE '%:\\Windows\\fonts\\%' OR CommandLine LIKE '%:\\Windows\\help\\%' OR CommandLine LIKE '%:\\Windows\\system32\\tasks\\%' OR CommandLine LIKE '%:\\Windows\\Tasks\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%\\Downloads\\%' OR CommandLine LIKE '%\\Local Settings\\Temporary Internet Files\\%' OR CommandLine LIKE '%\\Temporary Internet Files\\Content.Outlook\\%' OR CommandLine LIKE '%%Public%\\%' OR CommandLine LIKE '%%TEMP%%' OR CommandLine LIKE '%%TMP%%')))
