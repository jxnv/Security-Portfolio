-- Title: Syslog Clearing or Removal Via System Utilities
-- ID: 3fcc9b35-39e4-44c0-a2ad-9e82b6902b31
-- Status: test
-- Level: high
-- Author: Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date: 2021-10-15
-- Tags: attack.defense-impairment, attack.t1685.006
-- Description: Detects specific commands commonly used to remove or empty the syslog. Which is a technique often used by attacker as a method to hide their tracks
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%/var/log/syslog%') AND ((Image="*/cp" AND CommandLine LIKE '%/dev/null%') OR (Image="*/ln" AND (CommandLine LIKE '%/dev/null %' AND CommandLine LIKE '%/var/log/syslog%') AND (CommandLine LIKE '%-sf %' OR CommandLine LIKE '%-sfn %' OR CommandLine LIKE '%-sfT %')) OR (Image="*/mv") OR (Image="*/rm" AND (CommandLine LIKE '% -r %' OR CommandLine LIKE '% -f %' OR CommandLine LIKE '% -rf %' OR CommandLine LIKE '%/var/log/syslog%')) OR (Image="*/shred" AND CommandLine LIKE '%-u %') OR (Image="*/truncate" AND (CommandLine LIKE '%0 %' AND CommandLine LIKE '%/var/log/syslog%') AND (CommandLine LIKE '%-s %' OR CommandLine LIKE '%-c %' OR CommandLine LIKE '%--size%')) OR (Image="*/unlink"))) OR (((CommandLine LIKE '%journalctl --vacuum%' OR CommandLine LIKE '%journalctl --rotate%')) OR ((CommandLine LIKE '% > /var/log/syslog%' OR CommandLine LIKE '% >/var/log/syslog%' OR CommandLine LIKE '% >| /var/log/syslog%' OR CommandLine LIKE '%: > /var/log/syslog%' OR CommandLine LIKE '%:> /var/log/syslog%' OR CommandLine LIKE '%:>/var/log/syslog%' OR CommandLine LIKE '%>|/var/log/syslog%'))))
