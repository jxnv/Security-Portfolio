-- Title: Potential Discovery Activity Using Find - Linux
-- ID: 8344c0e5-5783-47cc-9cf9-a0f7fd03e6cf
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-28
-- Tags: attack.discovery, attack.t1083
-- Description: Detects usage of "find" binary in a suspicious manner to perform discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%/find' AND (CommandLine ILIKE '%-perm -4000%' OR CommandLine ILIKE '%-perm -2000%' OR CommandLine ILIKE '%-perm 0777%' OR CommandLine ILIKE '%-perm -222%' OR CommandLine ILIKE '%-perm -o w%' OR CommandLine ILIKE '%-perm -o x%' OR CommandLine ILIKE '%-perm -u=s%' OR CommandLine ILIKE '%-perm -g=s%'))
