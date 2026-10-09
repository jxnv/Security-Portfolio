-- Title: Obfuscated IP Download Activity
-- ID: cb5a2333-56cf-4562-8fcb-22ba1bca728d
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), X__Junior (Nextron Systems)
-- Date: 2022-08-03
-- Tags: attack.discovery
-- Description: Detects use of an encoded/obfuscated version of an IP address (hex, octal...) in an URL combined with a download command
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%Invoke-WebRequest%' OR CommandLine ILIKE '%iwr %' OR CommandLine ILIKE '%Invoke-RestMethod%' OR CommandLine ILIKE '%irm %' OR CommandLine ILIKE '%wget %' OR CommandLine ILIKE '%curl %' OR CommandLine ILIKE '%DownloadFile%' OR CommandLine ILIKE '%DownloadString%')) AND (((CommandLine ILIKE '% 0x%' OR CommandLine ILIKE '%//0x%' OR CommandLine ILIKE '%.0x%' OR CommandLine ILIKE '%.00x%')) OR ((CommandLine ILIKE '%http://%%' AND CommandLine ILIKE '%%2e%')) OR ((REGEXP_LIKE(CommandLine, 'https?://[0-9]{1,3}\.[0-9]{1,3}\.0[0-9]{3,4}')) OR (REGEXP_LIKE(CommandLine, 'https?://[0-9]{1,3}\.0[0-9]{3,7}')) OR (REGEXP_LIKE(CommandLine, 'https?://0[0-9]{3,11}')) OR (REGEXP_LIKE(CommandLine, 'https?://(?:0[0-9]{1,11}\.){3}0[0-9]{1,11}')) OR (REGEXP_LIKE(CommandLine, 'https?://0[0-9]{1,11}')) OR (REGEXP_LIKE(CommandLine, ' [0-7]{7,13}')))) AND NOT ((REGEXP_LIKE(CommandLine, 'https?://(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9])?\d)(?:\.|\b)){4}'))))
