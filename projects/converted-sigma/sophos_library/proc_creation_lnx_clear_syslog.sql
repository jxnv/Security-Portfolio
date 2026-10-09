-- Title: Syslog Clearing or Removal Via System Utilities
-- ID: 3fcc9b35-39e4-44c0-a2ad-9e82b6902b31
-- Status: test
-- Level: high
-- Author: Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date: 2021-10-15
-- Tags: attack.defense-impairment, attack.t1685.006
-- Description: Detects specific commands commonly used to remove or empty the syslog. Which is a technique often used by attacker as a method to hide their tracks
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%/var/log/syslog%') AND ((Image ILIKE '%/cp' AND CommandLine ILIKE '%/dev/null%') OR (Image ILIKE '%/ln' AND (CommandLine ILIKE '%/dev/null %' AND CommandLine ILIKE '%/var/log/syslog%') AND (CommandLine ILIKE '%-sf %' OR CommandLine ILIKE '%-sfn %' OR CommandLine ILIKE '%-sfT %')) OR (Image ILIKE '%/mv') OR (Image ILIKE '%/rm' AND (CommandLine ILIKE '% -r %' OR CommandLine ILIKE '% -f %' OR CommandLine ILIKE '% -rf %' OR CommandLine ILIKE '%/var/log/syslog%')) OR (Image ILIKE '%/shred' AND CommandLine ILIKE '%-u %') OR (Image ILIKE '%/truncate' AND (CommandLine ILIKE '%0 %' AND CommandLine ILIKE '%/var/log/syslog%') AND (CommandLine ILIKE '%-s %' OR CommandLine ILIKE '%-c %' OR CommandLine ILIKE '%--size%')) OR (Image ILIKE '%/unlink'))) OR (((CommandLine ILIKE '%journalctl --vacuum%' OR CommandLine ILIKE '%journalctl --rotate%')) OR ((CommandLine ILIKE '% > /var/log/syslog%' OR CommandLine ILIKE '% >/var/log/syslog%' OR CommandLine ILIKE '% >| /var/log/syslog%' OR CommandLine ILIKE '%: > /var/log/syslog%' OR CommandLine ILIKE '%:> /var/log/syslog%' OR CommandLine ILIKE '%:>/var/log/syslog%' OR CommandLine ILIKE '%>|/var/log/syslog%'))))
