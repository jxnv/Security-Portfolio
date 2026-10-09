-- Title: Cscript/Wscript Uncommon Script Extension Execution
-- ID: 99b7460d-c9f1-40d7-a316-1f36f61d52ee
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-15
-- Tags: attack.execution, attack.t1059.005, attack.t1059.007
-- Description: Detects Wscript/Cscript executing a file with an uncommon (i.e. non-script) extension
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.csv%' OR CommandLine LIKE '%.dat%' OR CommandLine LIKE '%.doc%' OR CommandLine LIKE '%.gif%' OR CommandLine LIKE '%.jpeg%' OR CommandLine LIKE '%.jpg%' OR CommandLine LIKE '%.png%' OR CommandLine LIKE '%.ppt%' OR CommandLine LIKE '%.txt%' OR CommandLine LIKE '%.xls%' OR CommandLine LIKE '%.xml%')) AND (((OriginalFileName = 'wscript.exe' OR OriginalFileName = 'cscript.exe')) OR ((Image="*\\wscript.exe" OR Image="*\\cscript.exe"))))
