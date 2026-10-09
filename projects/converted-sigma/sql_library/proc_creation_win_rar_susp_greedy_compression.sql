-- Title: Suspicious Greedy Compression Using Rar.EXE
-- ID: afe52666-401e-4a02-b4ff-5d128990b8cb
-- Status: test
-- Level: high
-- Author: X__Junior (Nextron Systems), Florian Roth (Nextron Systems)
-- Date: 2022-12-15
-- Tags: attack.execution, attack.t1059
-- Description: Detects RAR usage that creates an archive from a suspicious folder, either a system folder or one of the folders often used by attackers for staging purposes
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\rar.exe') OR (Description = 'Command line RAR')) OR ((CommandLine ILIKE '%.exe a %' OR CommandLine ILIKE '% a -m%'))) AND (((CommandLine ILIKE '% -hp%' AND CommandLine ILIKE '% -r %')) AND ((CommandLine ILIKE '% ?:\\\\\\*.%' OR CommandLine ILIKE '% ?:\\\\\\\\\\*.%' OR CommandLine ILIKE '% ?:\\$Recycle.bin\\%' OR CommandLine ILIKE '% ?:\\PerfLogs\\%' OR CommandLine ILIKE '% ?:\\Temp%' OR CommandLine ILIKE '% ?:\\Users\\Public\\%' OR CommandLine ILIKE '% ?:\\Windows\\%' OR CommandLine ILIKE '% %public%%'))))
