-- Title: Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE
-- ID: a35f5a72-f347-4e36-8895-9869b0d5fc6d
-- Status: test
-- Level: high
-- Author: Sander Wiebing, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
-- Date: 2020-05-25
-- Tags: attack.defense-impairment, attack.t1686.003
-- Description: Detects Netsh command execution that whitelists a program located in a suspicious location in the Windows Firewall
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%firewall%' AND CommandLine ILIKE '%add%' AND CommandLine ILIKE '%allowedprogram%')) OR ((CommandLine ILIKE '%advfirewall%' AND CommandLine ILIKE '%firewall%' AND CommandLine ILIKE '%add%' AND CommandLine ILIKE '%rule%' AND CommandLine ILIKE '%action=allow%' AND CommandLine ILIKE '%program=%'))) AND ((Image ILIKE '%\\netsh.exe') OR (OriginalFileName = 'netsh.exe')) AND ((CommandLine ILIKE '%:\\$Recycle.bin\\%' OR CommandLine ILIKE '%:\\RECYCLER.BIN\\%' OR CommandLine ILIKE '%:\\RECYCLERS.BIN\\%' OR CommandLine ILIKE '%:\\SystemVolumeInformation\\%' OR CommandLine ILIKE '%:\\Temp\\%' OR CommandLine ILIKE '%:\\Users\\Default\\%' OR CommandLine ILIKE '%:\\Users\\Desktop\\%' OR CommandLine ILIKE '%:\\Users\\Public\\%' OR CommandLine ILIKE '%:\\Windows\\addins\\%' OR CommandLine ILIKE '%:\\Windows\\cursors\\%' OR CommandLine ILIKE '%:\\Windows\\debug\\%' OR CommandLine ILIKE '%:\\Windows\\drivers\\%' OR CommandLine ILIKE '%:\\Windows\\fonts\\%' OR CommandLine ILIKE '%:\\Windows\\help\\%' OR CommandLine ILIKE '%:\\Windows\\system32\\tasks\\%' OR CommandLine ILIKE '%:\\Windows\\Tasks\\%' OR CommandLine ILIKE '%:\\Windows\\Temp\\%' OR CommandLine ILIKE '%\\Downloads\\%' OR CommandLine ILIKE '%\\Local Settings\\Temporary Internet Files\\%' OR CommandLine ILIKE '%\\Temporary Internet Files\\Content.Outlook\\%' OR CommandLine ILIKE '%%Public%\\%' OR CommandLine ILIKE '%%TEMP%%' OR CommandLine ILIKE '%%TMP%%')))
