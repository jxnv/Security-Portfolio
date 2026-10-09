-- Title: Suspicious Response File Execution Via Odbcconf.EXE
-- ID: 2d32dd6f-3196-4093-b9eb-1ad8ab088ca5
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-22
-- Tags: attack.stealth, attack.t1218.008
-- Description: Detects execution of "odbcconf" with the "-f" flag in order to load a response file with a non-".rsp" extension.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% -f %') AND ((Image ILIKE '%\\odbcconf.exe') OR (OriginalFileName = 'odbcconf.exe'))) AND NOT (((CommandLine ILIKE '%.rsp%') OR (ParentImage = 'C:\\Windows\\System32\\runonce.exe' AND Image = 'C:\\Windows\\System32\\odbcconf.exe' AND CommandLine ILIKE '%.exe /E /F \"C:\\WINDOWS\\system32\\odbcconf.tmp\"%'))))
