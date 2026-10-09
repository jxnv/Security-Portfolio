-- Title: Suspicious Download from Office Domain
-- ID: 00d49ed5-4491-4271-a8db-650a4ef6f8c1
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-12-27
-- Tags: attack.command-and-control, attack.resource-development, attack.t1105, attack.t1608
-- Description: Detects suspicious ways to download files from Microsoft domains that are used to store attachments in Emails or OneNote documents
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%https://attachment.outlook.live.net/owa/%' OR CommandLine ILIKE '%https://onenoteonlinesync.onenote.com/onenoteonlinesync/%')) AND (((Image ILIKE '%\\curl.exe' OR Image ILIKE '%\\wget.exe')) OR ((CommandLine ILIKE '%Invoke-WebRequest%' OR CommandLine ILIKE '%iwr %' OR CommandLine ILIKE '%curl %' OR CommandLine ILIKE '%wget %' OR CommandLine ILIKE '%Start-BitsTransfer%' OR CommandLine ILIKE '%.DownloadFile(%' OR CommandLine ILIKE '%.DownloadString(%'))))
