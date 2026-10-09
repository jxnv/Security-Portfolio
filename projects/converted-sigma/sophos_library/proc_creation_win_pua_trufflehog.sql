-- Title: PUA - TruffleHog Execution
-- ID: 44030449-b0df-4c94-aae1-502359ab28ee
-- Status: experimental
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-09-24
-- Tags: attack.discovery, attack.credential-access, attack.t1083, attack.t1552.001
-- Description: Detects execution of TruffleHog, a tool used to search for secrets in different platforms like Git, Jira, Slack, SharePoint, etc. that could be used maliciously.
-- While it is a legitimate tool, intended for use in CI pipelines and security assessments,
-- It was observed in the Shai-Hulud malware campaign targeting npm packages to steal sensitive information.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\trufflehog.exe') OR (((CommandLine ILIKE '% docker --image %' OR CommandLine ILIKE '% Git %' OR CommandLine ILIKE '% GitHub %' OR CommandLine ILIKE '% Jira %' OR CommandLine ILIKE '% Slack %' OR CommandLine ILIKE '% Confluence %' OR CommandLine ILIKE '% SharePoint %' OR CommandLine ILIKE '% s3 %' OR CommandLine ILIKE '% gcs %')) AND (CommandLine ILIKE '% --results=verified%')))
