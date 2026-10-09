-- Title: Local System Accounts Discovery - Linux
-- ID: b45e3d6f-42c6-47d8-a478-df6bd6cf534c
-- Status: test
-- Level: low
-- Author: Alejandro Ortuno, oscd.community, CheraghiMilad
-- Date: 2020-10-08
-- Tags: attack.discovery, attack.t1087.001
-- Description: Detects enumeration of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%/lastlog') OR (CommandLine ILIKE '%'x:0:'%') OR ((Image ILIKE '%/cat' OR Image ILIKE '%/ed' OR Image ILIKE '%/head' OR Image ILIKE '%/more' OR Image ILIKE '%/nano' OR Image ILIKE '%/tail' OR Image ILIKE '%/vi' OR Image ILIKE '%/vim' OR Image ILIKE '%/less' OR Image ILIKE '%/emacs' OR Image ILIKE '%/sqlite3' OR Image ILIKE '%/makemap') AND (CommandLine ILIKE '%/etc/passwd%' OR CommandLine ILIKE '%/etc/shadow%' OR CommandLine ILIKE '%/etc/sudoers%' OR CommandLine ILIKE '%/etc/spwd.db%' OR CommandLine ILIKE '%/etc/pwd.db%' OR CommandLine ILIKE '%/etc/master.passwd%')) OR (Image ILIKE '%/id') OR (Image ILIKE '%/lsof' AND CommandLine ILIKE '%-u%'))
