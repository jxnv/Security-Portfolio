-- Title: Cscript/Wscript Uncommon Script Extension Execution
-- ID: 99b7460d-c9f1-40d7-a316-1f36f61d52ee
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-15
-- Tags: attack.execution, attack.t1059.005, attack.t1059.007
-- Description: Detects Wscript/Cscript executing a file with an uncommon (i.e. non-script) extension
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%.csv%' OR CommandLine ILIKE '%.dat%' OR CommandLine ILIKE '%.doc%' OR CommandLine ILIKE '%.gif%' OR CommandLine ILIKE '%.jpeg%' OR CommandLine ILIKE '%.jpg%' OR CommandLine ILIKE '%.png%' OR CommandLine ILIKE '%.ppt%' OR CommandLine ILIKE '%.txt%' OR CommandLine ILIKE '%.xls%' OR CommandLine ILIKE '%.xml%')) AND (((OriginalFileName = 'wscript.exe' OR OriginalFileName = 'cscript.exe')) OR ((Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\cscript.exe'))))
