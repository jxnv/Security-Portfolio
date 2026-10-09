// Title: Renamed NetSupport RAT Execution
// ID: 0afbd410-de03-4078-8491-f132303cb67d
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-19
// Tags: attack.stealth
// Description: Detects the execution of a renamed "client32.exe" (NetSupport RAT) via Imphash, Product and OriginalFileName strings
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((Product contains "NetSupport Remote Control") or (action_process_image_name contains "client32.exe") or (Hashes contains "IMPHASH=A9D50692E95B79723F3E76FCF70D023E")) and not ((action_process_image_path endswith "\\client32.exe")))
