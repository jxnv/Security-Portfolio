-- Title: XSL Script Execution Via WMIC.EXE
-- ID: 05c36dd6-79d6-4a9a-97da-3db20298ab2d
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community, Swachchhanda Shrawan Poudel
-- Date: 2019-10-21
-- Tags: attack.stealth, attack.t1047, attack.t1220, attack.execution, attack.t1059.005, attack.t1059.007
-- Description: Detects the execution of WMIC with the "format" flag to potentially load local XSL files.
-- Adversaries abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.
-- Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%-format:%' OR CommandLine LIKE '%/format:%')) AND ((Image="*\\wmic.exe") OR (OriginalFileName = 'wmic.exe') OR ((Hashes LIKE '%IMPHASH=1B1A3F43BF37B5BFE60751F2EE2F326E%' OR Hashes LIKE '%IMPHASH=37777A96245A3C74EB217308F3546F4C%' OR Hashes LIKE '%IMPHASH=9D87C9D67CE724033C0B40CC4CA1B206%' OR Hashes LIKE '%IMPHASH=B12619881D79C3ACADF45E752A58554A%' OR Hashes LIKE '%IMPHASH=16A48C3CABF98A9DC1BF02C07FE1EA00%')))) AND NOT ((((CommandLine LIKE '%Format:List%' OR CommandLine LIKE '%Format:htable%' OR CommandLine LIKE '%Format:hform%' OR CommandLine LIKE '%Format:table%' OR CommandLine LIKE '%Format:mof%' OR CommandLine LIKE '%Format:value%' OR CommandLine LIKE '%Format:rawxml%' OR CommandLine LIKE '%Format:xml%' OR CommandLine LIKE '%Format:csv%')) OR ((CommandLine LIKE '%://%' OR CommandLine LIKE '%\\\\\\\\%')))))
