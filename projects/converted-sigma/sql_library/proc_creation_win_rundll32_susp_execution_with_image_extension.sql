-- Title: Suspicious Rundll32 Execution With Image Extension
-- ID: 4aa6040b-3f28-44e3-a769-9208e5feb5ec
-- Status: test
-- Level: high
-- Author: Hieu Tran
-- Date: 2023-03-13
-- Tags: attack.stealth, attack.t1218.011
-- Description: Detects the execution of Rundll32.exe with DLL files masquerading as image files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%.bmp%' OR CommandLine ILIKE '%.cr2%' OR CommandLine ILIKE '%.eps%' OR CommandLine ILIKE '%.gif%' OR CommandLine ILIKE '%.ico%' OR CommandLine ILIKE '%.jpeg%' OR CommandLine ILIKE '%.jpg%' OR CommandLine ILIKE '%.nef%' OR CommandLine ILIKE '%.orf%' OR CommandLine ILIKE '%.png%' OR CommandLine ILIKE '%.raw%' OR CommandLine ILIKE '%.sr2%' OR CommandLine ILIKE '%.tif%' OR CommandLine ILIKE '%.tiff%')) AND ((Image ILIKE '%\\rundll32.exe') OR (OriginalFileName = 'RUNDLL32.exe')))
