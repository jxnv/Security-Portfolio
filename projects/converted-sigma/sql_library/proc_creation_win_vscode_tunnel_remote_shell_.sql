-- Title: Visual Studio Code Tunnel Shell Execution
-- ID: f4a623c2-4ef5-4c33-b811-0642f702c9f1
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-10-25
-- Tags: attack.command-and-control, attack.t1071.001
-- Description: Detects the execution of a shell (powershell, bash, wsl...) via Visual Studio Code tunnel. Attackers can abuse this functionality to establish a C2 channel and execute arbitrary commands on the system.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ParentImage ILIKE '%\\servers\\Stable-%' AND ParentImage ILIKE '%\\server\\node.exe' AND ParentCommandLine ILIKE '%.vscode-server%') AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe') AND CommandLine ILIKE '%\\terminal\\browser\\media\\shellIntegration.ps1%') OR ((Image ILIKE '%\\wsl.exe' OR Image ILIKE '%\\bash.exe'))))
