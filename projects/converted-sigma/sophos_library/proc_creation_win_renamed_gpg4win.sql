-- Title: Renamed Gpg.EXE Execution
-- ID: ec0722a3-eb5c-4a56-8ab2-bf6f20708592
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2023-08-09
-- Tags: attack.impact, attack.t1486
-- Description: Detects the execution of a renamed "gpg.exe". Often used by ransomware and loaders to decrypt/encrypt data.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((OriginalFileName = 'gpg.exe') AND NOT (((Image ILIKE '%\\gpg.exe' OR Image ILIKE '%\\gpg2.exe'))))
