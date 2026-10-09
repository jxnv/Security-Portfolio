-- Title: Potential Suspicious Change To Sensitive/Critical Files
-- ID: 86157017-c2b1-4d4a-8c33-93b8e67e4af4
-- Status: test
-- Level: medium
-- Author: @d4ns4n_ (Wuerth-Phoenix)
-- Date: 2023-05-30
-- Tags: attack.impact, attack.t1565.001
-- Description: Detects changes of sensitive and critical files. Monitors files that you don't expect to change without planning on Linux system.
-- These files include, but are not limited to, system configuration files, authentication files, and critical application files.
-- Attackers often target these files to maintain persistence, escalate privileges, or disrupt system operations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((Image ILIKE '%/cat' OR Image ILIKE '%/echo' OR Image ILIKE '%/grep' OR Image ILIKE '%/head' OR Image ILIKE '%/more' OR Image ILIKE '%/tail') AND CommandLine ILIKE '%>%') OR ((Image ILIKE '%/emacs' OR Image ILIKE '%/nano' OR Image ILIKE '%/sed' OR Image ILIKE '%/vi' OR Image ILIKE '%/vim'))) AND ((CommandLine ILIKE '%/bin/login%' OR CommandLine ILIKE '%/bin/passwd%' OR CommandLine ILIKE '%/boot/%' OR CommandLine ILIKE '%/etc/*.conf%' OR CommandLine ILIKE '%/etc/cron.%' OR CommandLine ILIKE '%/etc/crontab%' OR CommandLine ILIKE '%/etc/hosts%' OR CommandLine ILIKE '%/etc/init.d%' OR CommandLine ILIKE '%/etc/sudoers%' OR CommandLine ILIKE '%/opt/bin/%' OR CommandLine ILIKE '%/sbin%' OR CommandLine ILIKE '%/usr/bin/%' OR CommandLine ILIKE '%/usr/local/bin/%')) AND NOT (1=1))
