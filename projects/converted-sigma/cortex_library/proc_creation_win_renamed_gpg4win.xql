// Title: Renamed Gpg.EXE Execution
// ID: ec0722a3-eb5c-4a56-8ab2-bf6f20708592
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), frack113
// Date: 2023-08-09
// Tags: attack.impact, attack.t1486
// Description: Detects the execution of a renamed "gpg.exe". Often used by ransomware and loaders to decrypt/encrypt data.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_name = "gpg.exe") and not (((action_process_image_path endswith "\\gpg.exe" or action_process_image_path endswith "\\gpg2.exe"))))
