-- Title: Office Macro File Creation From Suspicious Process
-- ID: b1c50487-1967-4315-a026-6491686d860e
-- Status: test
-- Level: high
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-01-23
-- Tags: attack.initial-access, attack.t1566.001
-- Description: Detects the creation of a office macro file from a a suspicious process
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe')) OR ((ParentImage ILIKE '%\\cscript.exe' OR ParentImage ILIKE '%\\mshta.exe' OR ParentImage ILIKE '%\\regsvr32.exe' OR ParentImage ILIKE '%\\rundll32.exe' OR ParentImage ILIKE '%\\wscript.exe'))) AND ((TargetFilename ILIKE '%.docm' OR TargetFilename ILIKE '%.dotm' OR TargetFilename ILIKE '%.xlsm' OR TargetFilename ILIKE '%.xltm' OR TargetFilename ILIKE '%.potm' OR TargetFilename ILIKE '%.pptm')))
