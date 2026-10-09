// Title: Remote Access Tool - AnyDesk Execution With Known Revoked Signing Certificate
// ID: 41f407b5-3096-44ea-a74f-96d04fbc41be
// Status: test
// Level: medium
// Author: Sai Prashanth Pulisetti, Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-02-08
// Tags: attack.execution, attack.initial-access
// Description: Detects the execution of an AnyDesk binary with a version prior to 8.0.8.
// Prior to version 8.0.8, the Anydesk application used a signing certificate that got compromised by threat actors.
// Use this rule to detect instances of older versions of Anydesk using the compromised certificate
// This is recommended in order to avoid attackers leveraging the certificate and signing their binaries to bypass detections.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\AnyDesk.exe") or (Description = "AnyDesk") or (Product = "AnyDesk") or (Company = "AnyDesk Software GmbH")) and ((FileVersion startswith "7.0." or FileVersion startswith "7.1." or FileVersion startswith "8.0.1" or FileVersion startswith "8.0.2" or FileVersion startswith "8.0.3" or FileVersion startswith "8.0.4" or FileVersion startswith "8.0.5" or FileVersion startswith "8.0.6" or FileVersion startswith "8.0.7"))) and not (((action_process_image_command_line contains " --remove" or action_process_image_command_line contains " --uninstall"))))
