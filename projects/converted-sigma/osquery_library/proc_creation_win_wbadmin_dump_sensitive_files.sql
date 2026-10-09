-- Title: Sensitive File Dump Via Wbadmin.EXE
-- ID: 8b93a509-1cb8-42e1-97aa-ee24224cdc15
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2024-05-10
-- Tags: attack.credential-access, attack.t1003.003
-- Description: Detects the dump of highly sensitive files such as "NTDS.DIT" and "SECURITY" hive.
-- Attackers can leverage the "wbadmin" utility in order to dump sensitive files that might contain credential or sensitive information.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%start%' OR CommandLine LIKE '%backup%')) AND ((Image="*\\wbadmin.exe") OR (OriginalFileName = 'WBADMIN.EXE')) AND ((CommandLine LIKE '%\\config\\SAM%' OR CommandLine LIKE '%\\config\\SECURITY%' OR CommandLine LIKE '%\\config\\SYSTEM%' OR CommandLine LIKE '%\\Windows\\NTDS\\NTDS.dit%')))
