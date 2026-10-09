-- Title: Linux Package Uninstall
-- ID: 95d61234-7f56-465c-6f2d-b562c6fedbc4
-- Status: test
-- Level: low
-- Author: Tuan Le (NCSGroup), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-03-09
-- Tags: attack.stealth, attack.t1070
-- Description: Detects linux package removal using builtin tools such as "yum", "apt", "apt-get" or "dpkg".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%/apt' OR Image ILIKE '%/apt-get') AND (CommandLine ILIKE '%remove%' OR CommandLine ILIKE '%purge%')) OR (Image ILIKE '%/dpkg' AND (CommandLine ILIKE '%--remove %' OR CommandLine ILIKE '% -r %')) OR (Image ILIKE '%/rpm' AND CommandLine ILIKE '% -e %') OR (Image ILIKE '%/yum' AND (CommandLine ILIKE '%erase%' OR CommandLine ILIKE '%remove%')))
