-- Title: Suspicious File Encoded To Base64 Via Certutil.EXE
-- ID: ea0cdc3e-2239-4f26-a947-4e8f8224e464
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-15
-- Tags: attack.stealth, attack.t1027
-- Description: Detects the execution of certutil with the "encode" flag to encode a file to base64 where the extensions of the file is suspicious
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%-encode%' OR CommandLine LIKE '%/encode%')) AND ((CommandLine LIKE '%.acl%' OR CommandLine LIKE '%.bat%' OR CommandLine LIKE '%.doc%' OR CommandLine LIKE '%.gif%' OR CommandLine LIKE '%.jpeg%' OR CommandLine LIKE '%.jpg%' OR CommandLine LIKE '%.mp3%' OR CommandLine LIKE '%.pdf%' OR CommandLine LIKE '%.png%' OR CommandLine LIKE '%.ppt%' OR CommandLine LIKE '%.tmp%' OR CommandLine LIKE '%.xls%' OR CommandLine LIKE '%.xml%')) AND ((Image="*\\certutil.exe") OR (OriginalFileName = 'CertUtil.exe')))
