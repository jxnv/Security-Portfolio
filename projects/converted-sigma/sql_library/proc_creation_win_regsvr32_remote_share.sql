-- Title: Suspicious Regsvr32 Execution From Remote Share
-- ID: 88a87a10-384b-4ad7-8871-2f9bf9259ce5
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-31
-- Tags: attack.stealth, attack.t1218.010
-- Description: Detects REGSVR32.exe to execute DLL hosted on remote shares
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '% \\\\\\\\%') AND ((Image ILIKE '%\\regsvr32.exe') OR (OriginalFileName = '\\REGSVR32.EXE')))
