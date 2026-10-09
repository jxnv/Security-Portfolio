-- Title: MMC Executing Files with Reversed Extensions Using RTLO Abuse
-- ID: 9cfe4b27-1e56-48b4-b7a8-d46851c91a44
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-02-05
-- Tags: attack.execution, attack.stealth, attack.t1204.002, attack.t1218.014, attack.t1036.002
-- Description: Detects malicious behavior where the MMC utility (`mmc.exe`) executes files with reversed extensions caused by Right-to-Left Override (RLO) abuse, disguising them as document formats.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%cod.msc%' OR CommandLine LIKE '%fdp.msc%' OR CommandLine LIKE '%ftr.msc%' OR CommandLine LIKE '%lmth.msc%' OR CommandLine LIKE '%slx.msc%' OR CommandLine LIKE '%tdo.msc%' OR CommandLine LIKE '%xcod.msc%' OR CommandLine LIKE '%xslx.msc%' OR CommandLine LIKE '%xtpp.msc%')) AND ((Image="*\\mmc.exe") OR (OriginalFileName = 'MMC.exe')))
