-- Title: Suspicious File Encoded To Base64 Via Certutil.EXE
-- ID: ea0cdc3e-2239-4f26-a947-4e8f8224e464
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-15
-- Tags: attack.stealth, attack.t1027
-- Description: Detects the execution of certutil with the "encode" flag to encode a file to base64 where the extensions of the file is suspicious
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%-encode%' OR CommandLine ILIKE '%/encode%')) AND ((CommandLine ILIKE '%.acl%' OR CommandLine ILIKE '%.bat%' OR CommandLine ILIKE '%.doc%' OR CommandLine ILIKE '%.gif%' OR CommandLine ILIKE '%.jpeg%' OR CommandLine ILIKE '%.jpg%' OR CommandLine ILIKE '%.mp3%' OR CommandLine ILIKE '%.pdf%' OR CommandLine ILIKE '%.png%' OR CommandLine ILIKE '%.ppt%' OR CommandLine ILIKE '%.tmp%' OR CommandLine ILIKE '%.xls%' OR CommandLine ILIKE '%.xml%')) AND ((Image ILIKE '%\\certutil.exe') OR (OriginalFileName = 'CertUtil.exe')))
