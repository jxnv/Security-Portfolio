-- Title: Renamed Visual Studio Code Tunnel Execution
-- ID: 2cf29f11-e356-4f61-98c0-1bdb9393d6da
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-09-28
-- Tags: attack.command-and-control, attack.t1071.001, attack.t1219
-- Description: Detects renamed Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((NOT OriginalFileName=* AND CommandLine="*.exe tunnel") OR ((CommandLine LIKE '%.exe tunnel%' AND CommandLine LIKE '%--accept-server-license-terms%')) OR ((CommandLine LIKE '%tunnel %' AND CommandLine LIKE '%service%' AND CommandLine LIKE '%internal-run%' AND CommandLine LIKE '%tunnel-service.log%'))) AND NOT (((Image="*\\code-tunnel.exe" OR Image="*\\code.exe")))) OR ((ParentCommandLine="* tunnel" AND Image="*\\cmd.exe" AND (CommandLine LIKE '%/d /c %' AND CommandLine LIKE '%\\servers\\Stable-%' AND CommandLine LIKE '%code-server.cmd%')) AND NOT (((ParentImage="*\\code-tunnel.exe" OR ParentImage="*\\code.exe")))))
