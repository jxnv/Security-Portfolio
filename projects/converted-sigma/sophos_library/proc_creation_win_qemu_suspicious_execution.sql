-- Title: Potentially Suspicious Usage Of Qemu
-- ID: 5fc297ae-25b6-488a-8f25-cc12ac29b744
-- Status: test
-- Level: medium
-- Author: Muhammad Faisal (@faisalusuf), Hunter Juhan (@threatHNTR)
-- Date: 2024-06-03
-- Tags: attack.command-and-control, attack.t1090, attack.t1572
-- Description: Detects potentially suspicious execution of the Qemu utility in a Windows environment.
-- Threat actors have leveraged this utility and this technique for achieving network access as reported by Kaspersky.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%-m 1M%' OR CommandLine ILIKE '%-m 2M%' OR CommandLine ILIKE '%-m 3M%') AND (CommandLine ILIKE '%restrict=off%' AND CommandLine ILIKE '%-netdev %' AND CommandLine ILIKE '%connect=%' AND CommandLine ILIKE '%-nographic%')) AND NOT (((CommandLine ILIKE '% -cdrom %' OR CommandLine ILIKE '% type=virt %' OR CommandLine ILIKE '% -blockdev %'))))
