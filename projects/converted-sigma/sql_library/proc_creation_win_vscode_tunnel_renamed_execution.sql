-- Title: Renamed Visual Studio Code Tunnel Execution
-- ID: 2cf29f11-e356-4f61-98c0-1bdb9393d6da
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-09-28
-- Tags: attack.command-and-control, attack.t1071.001, attack.t1219
-- Description: Detects renamed Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((OriginalFileName IS NULL AND CommandLine ILIKE '%.exe tunnel') OR ((CommandLine ILIKE '%.exe tunnel%' AND CommandLine ILIKE '%--accept-server-license-terms%')) OR ((CommandLine ILIKE '%tunnel %' AND CommandLine ILIKE '%service%' AND CommandLine ILIKE '%internal-run%' AND CommandLine ILIKE '%tunnel-service.log%'))) AND NOT (((Image ILIKE '%\\code-tunnel.exe' OR Image ILIKE '%\\code.exe')))) OR ((ParentCommandLine ILIKE '% tunnel' AND Image ILIKE '%\\cmd.exe' AND (CommandLine ILIKE '%/d /c %' AND CommandLine ILIKE '%\\servers\\Stable-%' AND CommandLine ILIKE '%code-server.cmd%')) AND NOT (((ParentImage ILIKE '%\\code-tunnel.exe' OR ParentImage ILIKE '%\\code.exe')))))
