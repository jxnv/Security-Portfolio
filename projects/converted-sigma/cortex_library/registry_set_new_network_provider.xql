// Title: Potential Credential Dumping Attempt Using New NetworkProvider - REG
// ID: 0442defa-b4a2-41c9-ae2c-ea7042fc4701
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-23
// Tags: attack.credential-access, attack.t1003
// Description: Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\System\\CurrentControlSet\\Services\\" and TargetObject contains "\\NetworkProvider")) and not ((((TargetObject contains "\\System\\CurrentControlSet\\Services\\WebClient\\NetworkProvider" or TargetObject contains "\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\NetworkProvider" or TargetObject contains "\\System\\CurrentControlSet\\Services\\RDPNP\\NetworkProvider")) or (action_process_image_path = "C:\\Windows\\System32\\poqexec.exe"))))
