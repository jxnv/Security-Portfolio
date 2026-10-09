-- Title: Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE
-- ID: 37db85d1-b089-490a-a59a-c7b6f984f480
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2021-12-16
-- Tags: attack.discovery, attack.t1518.001
-- Description: Detects usage of "findstr" with the argument "385201". Which could indicate potential discovery of an installed Sysinternals Sysmon service using the default driver altitude (even if the name is changed).
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '% 385201%') AND (((Image ILIKE '%\\find.exe' OR Image ILIKE '%\\findstr.exe')) OR ((OriginalFileName = 'FIND.EXE' OR OriginalFileName = 'FINDSTR.EXE'))))
