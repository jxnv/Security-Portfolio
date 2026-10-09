-- Title: Visual Studio Code Tunnel Execution
-- ID: 90d6bd71-dffb-4989-8d86-a827fedd6624
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), citron_ninja
-- Date: 2023-10-25
-- Tags: attack.command-and-control, attack.t1071.001, attack.t1219
-- Description: Detects Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((OriginalFileName IS NULL AND CommandLine ILIKE '%.exe tunnel') OR (ParentCommandLine ILIKE '% tunnel' AND Image ILIKE '%\\cmd.exe' AND (CommandLine ILIKE '%/d /c %' AND CommandLine ILIKE '%\\servers\\Stable-%' AND CommandLine ILIKE '%code-server.cmd%')) OR ((CommandLine ILIKE '%.exe tunnel%' AND CommandLine ILIKE '%--accept-server-license-terms%')))
