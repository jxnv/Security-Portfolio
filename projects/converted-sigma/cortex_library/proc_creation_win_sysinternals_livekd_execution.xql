// Title: Potential Memory Dumping Activity Via LiveKD
// ID: a85f7765-698a-4088-afa0-ecfbf8d01fa4
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-15
// Tags: attack.stealth
// Description: Detects execution of LiveKD based on PE metadata or image name
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\livekd.exe" or action_process_image_path endswith "\\livekd64.exe")) or (action_process_image_name = "livekd.exe"))
