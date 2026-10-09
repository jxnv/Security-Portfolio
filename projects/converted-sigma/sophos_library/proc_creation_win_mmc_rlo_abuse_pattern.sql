-- Title: MMC Executing Files with Reversed Extensions Using RTLO Abuse
-- ID: 9cfe4b27-1e56-48b4-b7a8-d46851c91a44
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-02-05
-- Tags: attack.execution, attack.stealth, attack.t1204.002, attack.t1218.014, attack.t1036.002
-- Description: Detects malicious behavior where the MMC utility (`mmc.exe`) executes files with reversed extensions caused by Right-to-Left Override (RLO) abuse, disguising them as document formats.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%cod.msc%' OR CommandLine ILIKE '%fdp.msc%' OR CommandLine ILIKE '%ftr.msc%' OR CommandLine ILIKE '%lmth.msc%' OR CommandLine ILIKE '%slx.msc%' OR CommandLine ILIKE '%tdo.msc%' OR CommandLine ILIKE '%xcod.msc%' OR CommandLine ILIKE '%xslx.msc%' OR CommandLine ILIKE '%xtpp.msc%')) AND ((Image ILIKE '%\\mmc.exe') OR (OriginalFileName = 'MMC.exe')))
