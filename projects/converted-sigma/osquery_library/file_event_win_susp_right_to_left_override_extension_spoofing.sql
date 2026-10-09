-- Title: Potential File Extension Spoofing Using Right-to-Left Override
-- ID: 979baf41-ca44-4540-9d0c-4fcef3b5a3a4
-- Status: test
-- Level: high
-- Author: Jonathan Peters (Nextron Systems), Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2024-11-17
-- Tags: attack.execution, attack.stealth, attack.t1036.002
-- Description: Detects suspicious filenames that contain a right-to-left override character and a potentially spoofed file extensions.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetFilename LIKE '%3pm.%' OR TargetFilename LIKE '%4pm.%' OR TargetFilename LIKE '%cod.%' OR TargetFilename LIKE '%fdp.%' OR TargetFilename LIKE '%ftr.%' OR TargetFilename LIKE '%gepj.%' OR TargetFilename LIKE '%gnp.%' OR TargetFilename LIKE '%gpj.%' OR TargetFilename LIKE '%ism.%' OR TargetFilename LIKE '%lmth.%' OR TargetFilename LIKE '%nls.%' OR TargetFilename LIKE '%piz.%' OR TargetFilename LIKE '%slx.%' OR TargetFilename LIKE '%tdo.%' OR TargetFilename LIKE '%vsc.%' OR TargetFilename LIKE '%vwm.%' OR TargetFilename LIKE '%xcod.%' OR TargetFilename LIKE '%xslx.%' OR TargetFilename LIKE '%xtpp.%')) AND ((TargetFilename LIKE '%\\u202e%' OR TargetFilename LIKE '%[U+202E]%' OR TargetFilename LIKE '%‮%')))
