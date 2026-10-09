-- Title: Potential File Extension Spoofing Using Right-to-Left Override
-- ID: 979baf41-ca44-4540-9d0c-4fcef3b5a3a4
-- Status: test
-- Level: high
-- Author: Jonathan Peters (Nextron Systems), Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2024-11-17
-- Tags: attack.execution, attack.stealth, attack.t1036.002
-- Description: Detects suspicious filenames that contain a right-to-left override character and a potentially spoofed file extensions.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetFilename ILIKE '%3pm.%' OR TargetFilename ILIKE '%4pm.%' OR TargetFilename ILIKE '%cod.%' OR TargetFilename ILIKE '%fdp.%' OR TargetFilename ILIKE '%ftr.%' OR TargetFilename ILIKE '%gepj.%' OR TargetFilename ILIKE '%gnp.%' OR TargetFilename ILIKE '%gpj.%' OR TargetFilename ILIKE '%ism.%' OR TargetFilename ILIKE '%lmth.%' OR TargetFilename ILIKE '%nls.%' OR TargetFilename ILIKE '%piz.%' OR TargetFilename ILIKE '%slx.%' OR TargetFilename ILIKE '%tdo.%' OR TargetFilename ILIKE '%vsc.%' OR TargetFilename ILIKE '%vwm.%' OR TargetFilename ILIKE '%xcod.%' OR TargetFilename ILIKE '%xslx.%' OR TargetFilename ILIKE '%xtpp.%')) AND ((TargetFilename ILIKE '%\\u202e%' OR TargetFilename ILIKE '%[U+202E]%' OR TargetFilename ILIKE '%‮%')))
