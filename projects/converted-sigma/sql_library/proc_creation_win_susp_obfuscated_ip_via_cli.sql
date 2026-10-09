-- Title: Obfuscated IP Via CLI
-- ID: 56d19cb4-6414-4769-9644-1ed35ffbb148
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
-- Date: 2022-08-03
-- Tags: attack.discovery
-- Description: Detects usage of an encoded/obfuscated version of an IP address (hex, octal, etc.) via command line
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\ping.exe' OR Image ILIKE '%\\arp.exe')) AND (((CommandLine ILIKE '% 0x%' OR CommandLine ILIKE '%//0x%' OR CommandLine ILIKE '%.0x%' OR CommandLine ILIKE '%.00x%')) OR ((CommandLine ILIKE '%http://%%' AND CommandLine ILIKE '%%2e%')) OR ((REGEXP_LIKE(CommandLine, 'https?://[0-9]{1,3}\.[0-9]{1,3}\.0[0-9]{3,4}')) OR (REGEXP_LIKE(CommandLine, 'https?://[0-9]{1,3}\.0[0-9]{3,7}')) OR (REGEXP_LIKE(CommandLine, 'https?://0[0-9]{3,11}')) OR (REGEXP_LIKE(CommandLine, 'https?://(?:0[0-9]{1,11}\.){3}0[0-9]{1,11}')) OR (REGEXP_LIKE(CommandLine, 'https?://0[0-9]{1,11}')) OR (REGEXP_LIKE(CommandLine, ' [0-7]{7,13}')))) AND NOT ((REGEXP_LIKE(CommandLine, 'https?://(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9])?\d)(?:\.|\b)){4}'))))
