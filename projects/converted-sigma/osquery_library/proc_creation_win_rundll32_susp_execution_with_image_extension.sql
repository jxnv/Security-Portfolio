-- Title: Suspicious Rundll32 Execution With Image Extension
-- ID: 4aa6040b-3f28-44e3-a769-9208e5feb5ec
-- Status: test
-- Level: high
-- Author: Hieu Tran
-- Date: 2023-03-13
-- Tags: attack.stealth, attack.t1218.011
-- Description: Detects the execution of Rundll32.exe with DLL files masquerading as image files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.bmp%' OR CommandLine LIKE '%.cr2%' OR CommandLine LIKE '%.eps%' OR CommandLine LIKE '%.gif%' OR CommandLine LIKE '%.ico%' OR CommandLine LIKE '%.jpeg%' OR CommandLine LIKE '%.jpg%' OR CommandLine LIKE '%.nef%' OR CommandLine LIKE '%.orf%' OR CommandLine LIKE '%.png%' OR CommandLine LIKE '%.raw%' OR CommandLine LIKE '%.sr2%' OR CommandLine LIKE '%.tif%' OR CommandLine LIKE '%.tiff%')) AND ((Image="*\\rundll32.exe") OR (OriginalFileName = 'RUNDLL32.exe')))
