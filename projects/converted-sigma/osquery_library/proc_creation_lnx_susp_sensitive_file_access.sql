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

SELECT * FROM processes WHERE ((((Image="*/cat" OR Image="*/echo" OR Image="*/grep" OR Image="*/head" OR Image="*/more" OR Image="*/tail") AND CommandLine LIKE '%>%') OR ((Image="*/emacs" OR Image="*/nano" OR Image="*/sed" OR Image="*/vi" OR Image="*/vim"))) AND ((CommandLine LIKE '%/bin/login%' OR CommandLine LIKE '%/bin/passwd%' OR CommandLine LIKE '%/boot/%' OR CommandLine LIKE '%/etc/*.conf%' OR CommandLine LIKE '%/etc/cron.%' OR CommandLine LIKE '%/etc/crontab%' OR CommandLine LIKE '%/etc/hosts%' OR CommandLine LIKE '%/etc/init.d%' OR CommandLine LIKE '%/etc/sudoers%' OR CommandLine LIKE '%/opt/bin/%' OR CommandLine LIKE '%/sbin%' OR CommandLine LIKE '%/usr/bin/%' OR CommandLine LIKE '%/usr/local/bin/%')) AND NOT (1=1))
