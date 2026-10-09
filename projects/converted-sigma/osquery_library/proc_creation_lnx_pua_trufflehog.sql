-- Title: PUA - TruffleHog Execution - Linux
-- ID: d7a650c4-226c-451e-948f-cc490db506aa
-- Status: experimental
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-09-24
-- Tags: attack.discovery, attack.credential-access, attack.t1083, attack.t1552.001
-- Description: Detects execution of TruffleHog, a tool used to search for secrets in different platforms like Git, Jira, Slack, SharePoint, etc. that could be used maliciously.
-- While it is a legitimate tool, intended for use in CI pipelines and security assessments,
-- It was observed in the Shai-Hulud malware campaign targeting npm packages to steal sensitive information.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/trufflehog") OR (((CommandLine LIKE '% docker --image %' OR CommandLine LIKE '% Git %' OR CommandLine LIKE '% GitHub %' OR CommandLine LIKE '% Jira %' OR CommandLine LIKE '% Slack %' OR CommandLine LIKE '% Confluence %' OR CommandLine LIKE '% SharePoint %' OR CommandLine LIKE '% s3 %' OR CommandLine LIKE '% gcs %')) AND (CommandLine LIKE '% --results=verified%')))
