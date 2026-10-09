-- Title: HackTool - Inveigh Execution
-- ID: b99a1518-1ad5-4f65-bc95-1ffff97a8fd0
-- Status: test
-- Level: critical
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-24
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects the use of Inveigh a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\Inveigh.exe") OR ((OriginalFileName = '\\Inveigh.exe' OR OriginalFileName = '\\Inveigh.dll')) OR (Description = 'Inveigh') OR ((CommandLine LIKE '% -SpooferIP%' OR CommandLine LIKE '% -ReplyToIPs %' OR CommandLine LIKE '% -ReplyToDomains %' OR CommandLine LIKE '% -ReplyToMACs %' OR CommandLine LIKE '% -SnifferIP%')))
