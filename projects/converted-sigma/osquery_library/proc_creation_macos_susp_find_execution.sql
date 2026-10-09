-- Title: Potential Discovery Activity Using Find - MacOS
-- ID: 85de3a19-b675-4a51-bfc6-b11a5186c971
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-28
-- Tags: attack.discovery, attack.t1083
-- Description: Detects usage of "find" binary in a suspicious manner to perform discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*/find" AND (CommandLine LIKE '%-perm -4000%' OR CommandLine LIKE '%-perm -2000%' OR CommandLine LIKE '%-perm 0777%' OR CommandLine LIKE '%-perm -222%' OR CommandLine LIKE '%-perm -o w%' OR CommandLine LIKE '%-perm -o x%' OR CommandLine LIKE '%-perm -u=s%' OR CommandLine LIKE '%-perm -g=s%'))
