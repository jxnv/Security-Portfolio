-- Title: Regsvr32 DLL Execution With Suspicious File Extension
-- ID: 089fc3d2-71e8-4763-a8a5-c97fbb0a403e
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), frack113
-- Date: 2021-11-29
-- Tags: attack.stealth, attack.t1218.010
-- Description: Detects the execution of REGSVR32.exe with DLL files masquerading as other files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%.bin' OR CommandLine ILIKE '%.bmp' OR CommandLine ILIKE '%.cr2' OR CommandLine ILIKE '%.dat' OR CommandLine ILIKE '%.eps' OR CommandLine ILIKE '%.gif' OR CommandLine ILIKE '%.ico' OR CommandLine ILIKE '%.jpeg' OR CommandLine ILIKE '%.jpg' OR CommandLine ILIKE '%.log' OR CommandLine ILIKE '%.nef' OR CommandLine ILIKE '%.orf' OR CommandLine ILIKE '%.png' OR CommandLine ILIKE '%.raw' OR CommandLine ILIKE '%.rtf' OR CommandLine ILIKE '%.sr2' OR CommandLine ILIKE '%.temp' OR CommandLine ILIKE '%.tif' OR CommandLine ILIKE '%.tiff' OR CommandLine ILIKE '%.tmp' OR CommandLine ILIKE '%.txt')) AND ((Image ILIKE '%\\regsvr32.exe') OR (OriginalFileName = 'REGSVR32.EXE')))
