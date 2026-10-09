-- Title: Visual Studio Code Tunnel Service Installation
-- ID: 30bf1789-379d-4fdc-900f-55cd0a90a801
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-10-25
-- Tags: attack.command-and-control, attack.t1071.001
-- Description: Detects the installation of VsCode tunnel (code-tunnel) as a service.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%tunnel %' AND CommandLine ILIKE '%service%' AND CommandLine ILIKE '%internal-run%' AND CommandLine ILIKE '%tunnel-service.log%'))
