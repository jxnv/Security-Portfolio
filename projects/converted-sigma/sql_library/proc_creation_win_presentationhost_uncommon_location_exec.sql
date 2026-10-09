-- Title: XBAP Execution From Uncommon Locations Via PresentationHost.EXE
-- ID: d22e2925-cfd8-463f-96f6-89cec9d9bc5f
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-01
-- Tags: attack.execution, attack.stealth, attack.t1218
-- Description: Detects the execution of ".xbap" (Browser Applications) files via PresentationHost.EXE from an uncommon location. These files can be abused to run malicious ".xbap" files any bypass AWL
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%.xbap%') AND ((Image ILIKE '%\\presentationhost.exe') OR (OriginalFileName = 'PresentationHost.exe'))) AND NOT (((CommandLine ILIKE '% C:\\Windows\\%' OR CommandLine ILIKE '% C:\\Program Files%'))))
