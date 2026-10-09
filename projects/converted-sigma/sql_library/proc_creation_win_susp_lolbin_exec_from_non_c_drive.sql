-- Title: LOLBIN Execution From Abnormal Drive
-- ID: d4ca7c59-e9e4-42d8-bf57-91a776efcb87
-- Status: test
-- Level: medium
-- Author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Angelo Violetti - SEC Consult '@angelo_violetti', Aaron Herman
-- Date: 2022-01-25
-- Tags: attack.stealth
-- Description: Detects LOLBINs executing from an abnormal or uncommon drive such as a mounted ISO.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\calc.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\cmstp.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\installutil.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe')) OR ((OriginalFileName = 'CALC.EXE' OR OriginalFileName = 'CertUtil.exe' OR OriginalFileName = 'CMSTP.EXE' OR OriginalFileName = 'cscript.exe' OR OriginalFileName = 'installutil.exe' OR OriginalFileName = 'MSHTA.EXE' OR OriginalFileName = 'REGSVR32.EXE' OR OriginalFileName = 'RUNDLL32.EXE' OR OriginalFileName = 'wscript.exe'))) AND NOT (((CurrentDirectory ILIKE '%C:\\%') OR (CurrentDirectory = '') OR (CurrentDirectory IS NULL))))
