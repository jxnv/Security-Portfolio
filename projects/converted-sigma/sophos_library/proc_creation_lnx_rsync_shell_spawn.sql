-- Title: Suspicious Invocation of Shell via Rsync
-- ID: 297241f3-8108-4b3a-8c15-2dda9f844594
-- Status: experimental
-- Level: high
-- Author: Florian Roth
-- Date: 2025-01-18
-- Tags: attack.execution, attack.t1059, attack.t1203
-- Description: Detects the execution of a shell as sub process of "rsync" without the expected command line flag "-e" being used, which could be an indication of exploitation as described in CVE-2024-12084. This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentImage ILIKE '%/rsync' OR ParentImage ILIKE '%/rsyncd') AND (Image ILIKE '%/ash' OR Image ILIKE '%/bash' OR Image ILIKE '%/csh' OR Image ILIKE '%/dash' OR Image ILIKE '%/ksh' OR Image ILIKE '%/sh' OR Image ILIKE '%/tcsh' OR Image ILIKE '%/zsh')) AND NOT ((CommandLine ILIKE '% -e %')))
