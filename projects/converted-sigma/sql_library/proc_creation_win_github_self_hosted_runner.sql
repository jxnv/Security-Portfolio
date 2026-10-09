-- Title: Github Self-Hosted Runner Execution
-- ID: 5bac7a56-da88-4c27-922e-c81e113b20cb
-- Status: test
-- Level: medium
-- Author: Daniel Koifman (KoifSec)
-- Date: 2025-11-29
-- Tags: attack.command-and-control, attack.t1102.002, attack.t1071
-- Description: Detects GitHub self-hosted runners executing workflows on local infrastructure that could be abused for persistence and code execution.
-- Shai-Hulud is an npm supply chain worm targeting CI/CD environments.
-- It installs runners on compromised systems to maintain access after credential theft, leveraging their access to secrets and internal networks.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%spawnclient%') AND ((Image ILIKE '%\\Runner.Worker.exe') OR (OriginalFileName = 'Runner.Worker.dll'))) OR (((CommandLine ILIKE '%run%' OR CommandLine ILIKE '%configure%')) AND ((Image ILIKE '%\\Runner.Listener.exe') OR (OriginalFileName = 'Runner.Listener.dll'))))
