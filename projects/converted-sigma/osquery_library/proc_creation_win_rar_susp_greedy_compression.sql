-- Title: Suspicious Greedy Compression Using Rar.EXE
-- ID: afe52666-401e-4a02-b4ff-5d128990b8cb
-- Status: test
-- Level: high
-- Author: X__Junior (Nextron Systems), Florian Roth (Nextron Systems)
-- Date: 2022-12-15
-- Tags: attack.execution, attack.t1059
-- Description: Detects RAR usage that creates an archive from a suspicious folder, either a system folder or one of the folders often used by attackers for staging purposes
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\rar.exe") OR (Description = 'Command line RAR')) OR ((CommandLine LIKE '%.exe a %' OR CommandLine LIKE '% a -m%'))) AND (((CommandLine LIKE '% -hp%' AND CommandLine LIKE '% -r %')) AND ((CommandLine LIKE '% ?:\\\\\\*.%' OR CommandLine LIKE '% ?:\\\\\\\\\\*.%' OR CommandLine LIKE '% ?:\\$Recycle.bin\\%' OR CommandLine LIKE '% ?:\\PerfLogs\\%' OR CommandLine LIKE '% ?:\\Temp%' OR CommandLine LIKE '% ?:\\Users\\Public\\%' OR CommandLine LIKE '% ?:\\Windows\\%' OR CommandLine LIKE '% %public%%'))))
