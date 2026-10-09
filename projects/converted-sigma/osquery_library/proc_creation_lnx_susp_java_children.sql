-- Title: Suspicious Java Children Processes
-- ID: d292e0af-9a18-420c-9525-ec0ac3936892
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-03
-- Tags: attack.execution, attack.t1059
-- Description: Detects java process spawning suspicious children
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (ParentImage="*/java" AND (CommandLine LIKE '%/bin/sh%' OR CommandLine LIKE '%bash%' OR CommandLine LIKE '%dash%' OR CommandLine LIKE '%ksh%' OR CommandLine LIKE '%zsh%' OR CommandLine LIKE '%csh%' OR CommandLine LIKE '%fish%' OR CommandLine LIKE '%curl%' OR CommandLine LIKE '%wget%' OR CommandLine LIKE '%python%'))
