-- Title: Sensitive File Dump Via Print.EXE
-- ID: 2fcda7e2-8c57-4904-86ac-37fc3157e09d
-- Status: test
-- Level: high
-- Author: Ayush Anand (Securityinbits)
-- Date: 2026-04-28
-- Tags: attack.credential-access, attack.stealth, attack.t1003.003, attack.t1003.002, attack.t1218
-- Description: Detects the abuse of the Print.exe utility for credential harvesting which involves using Print.Exe to copy sensitive files such as ntds.dit, SAM, SECURITY, or SYSTEM from the Windows directory in order to extract credentials, locally or remotely.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%/D%' OR CommandLine ILIKE '%-D%') AND (CommandLine ILIKE '%\\config\\SAM%' OR CommandLine ILIKE '%\\config\\SECURITY%' OR CommandLine ILIKE '%\\config\\SYSTEM%' OR CommandLine ILIKE '%\\windows\\ntds\\ntds.dit%')) AND ((Image ILIKE '%\\print.exe') OR (OriginalFileName = 'Print.EXE')))
