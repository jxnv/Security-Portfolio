// Title: DriverQuery.EXE Execution
// ID: a20def93-0709-4eae-9bd2-31206e21e6b2
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-19
// Tags: attack.discovery
// Description: Detect usage of the "driverquery" utility. Which can be used to perform reconnaissance on installed drivers
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "driverquery.exe") or (action_process_image_name = "drvqry.exe")) and not ((((actor_process_image_path endswith "\\cscript.exe" or actor_process_image_path endswith "\\mshta.exe" or actor_process_image_path endswith "\\regsvr32.exe" or actor_process_image_path endswith "\\rundll32.exe" or actor_process_image_path endswith "\\wscript.exe")) or ((actor_process_image_path contains "\\AppData\\Local\\" or actor_process_image_path contains "\\Users\\Public\\" or actor_process_image_path contains "\\Windows\\Temp\\")))))
