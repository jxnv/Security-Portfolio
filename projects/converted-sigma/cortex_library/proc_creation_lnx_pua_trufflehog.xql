// Title: PUA - TruffleHog Execution - Linux
// ID: d7a650c4-226c-451e-948f-cc490db506aa
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-09-24
// Tags: attack.discovery, attack.credential-access, attack.t1083, attack.t1552.001
// Description: Detects execution of TruffleHog, a tool used to search for secrets in different platforms like Git, Jira, Slack, SharePoint, etc. that could be used maliciously.
// While it is a legitimate tool, intended for use in CI pipelines and security assessments,
// It was observed in the Shai-Hulud malware campaign targeting npm packages to steal sensitive information.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/trufflehog") or (((action_process_image_command_line contains " docker --image " or action_process_image_command_line contains " Git " or action_process_image_command_line contains " GitHub " or action_process_image_command_line contains " Jira " or action_process_image_command_line contains " Slack " or action_process_image_command_line contains " Confluence " or action_process_image_command_line contains " SharePoint " or action_process_image_command_line contains " s3 " or action_process_image_command_line contains " gcs ")) and (action_process_image_command_line contains " --results=verified")))
