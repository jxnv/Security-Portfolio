// Title: PUA - TruffleHog Execution
// ID: 44030449-b0df-4c94-aae1-502359ab28ee
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-09-24
// Tags: attack.discovery, attack.credential-access, attack.t1083, attack.t1552.001
// Description: Detects execution of TruffleHog, a tool used to search for secrets in different platforms like Git, Jira, Slack, SharePoint, etc. that could be used maliciously.
// While it is a legitimate tool, intended for use in CI pipelines and security assessments,
// It was observed in the Shai-Hulud malware campaign targeting npm packages to steal sensitive information.
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\trufflehog.exe") OR (((CommandLine contains " docker --image " OR CommandLine contains " Git " OR CommandLine contains " GitHub " OR CommandLine contains " Jira " OR CommandLine contains " Slack " OR CommandLine contains " Confluence " OR CommandLine contains " SharePoint " OR CommandLine contains " s3 " OR CommandLine contains " gcs ")) AND (CommandLine contains " --results=verified")))
