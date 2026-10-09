-- Title: Sensitive File Recovery From Backup Via Wbadmin.EXE
-- ID: 84972c80-251c-4c3a-9079-4f00aad93938
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2024-05-10
-- Tags: attack.credential-access, attack.t1003.003
-- Description: Detects the dump of highly sensitive files such as "NTDS.DIT" and "SECURITY" hive.
-- Attackers can leverage the "wbadmin" utility in order to dump sensitive files that might contain credential or sensitive information.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% recovery%' AND CommandLine ILIKE '%recoveryTarget%' AND CommandLine ILIKE '%itemtype:File%') AND (CommandLine ILIKE '%\\config\\SAM%' OR CommandLine ILIKE '%\\config\\SECURITY%' OR CommandLine ILIKE '%\\config\\SYSTEM%' OR CommandLine ILIKE '%\\Windows\\NTDS\\NTDS.dit%')) AND ((Image ILIKE '%\\wbadmin.exe') OR (OriginalFileName = 'WBADMIN.EXE')))
