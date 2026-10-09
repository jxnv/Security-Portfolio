-- Title: Obfuscated IP Download Activity
-- ID: cb5a2333-56cf-4562-8fcb-22ba1bca728d
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), X__Junior (Nextron Systems)
-- Date: 2022-08-03
-- Tags: attack.discovery
-- Description: Detects use of an encoded/obfuscated version of an IP address (hex, octal...) in an URL combined with a download command
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Invoke-WebRequest%' OR CommandLine LIKE '%iwr %' OR CommandLine LIKE '%Invoke-RestMethod%' OR CommandLine LIKE '%irm %' OR CommandLine LIKE '%wget %' OR CommandLine LIKE '%curl %' OR CommandLine LIKE '%DownloadFile%' OR CommandLine LIKE '%DownloadString%')) AND (((CommandLine LIKE '% 0x%' OR CommandLine LIKE '%//0x%' OR CommandLine LIKE '%.0x%' OR CommandLine LIKE '%.00x%')) OR ((CommandLine LIKE '%http://%%' AND CommandLine LIKE '%%2e%')) OR ((CommandLine=regex("https?://[0-9]{1,3}\\.[0-9]{1,3}\\.0[0-9]{3,4}")) OR (CommandLine=regex("https?://[0-9]{1,3}\\.0[0-9]{3,7}")) OR (CommandLine=regex("https?://0[0-9]{3,11}")) OR (CommandLine=regex("https?://(?:0[0-9]{1,11}\\.){3}0[0-9]{1,11}")) OR (CommandLine=regex("https?://0[0-9]{1,11}")) OR (CommandLine=regex(" [0-7]{7,13}")))) AND NOT ((CommandLine=regex("https?://(?:(?:25[0-5]|(?:2[0-4]|1\\d|[1-9])?\\d)(?:\\.|\\b)){4}"))))
