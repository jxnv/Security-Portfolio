// Title: Potential Credential Dumping Attempt Using New NetworkProvider - CLI
// ID: baef1ec6-2ca9-47a3-97cc-4cf2bda10b77
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-23
// Tags: attack.credential-access, attack.t1003
// Description: Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "\\System\\CurrentControlSet\\Services\\" and action_process_image_command_line contains "\\NetworkProvider"))
