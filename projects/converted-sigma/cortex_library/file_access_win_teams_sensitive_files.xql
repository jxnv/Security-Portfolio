// Title: Microsoft Teams Sensitive File Access By Uncommon Applications
// ID: 65744385-8541-44a6-8630-ffc824d7d4cc
// Status: test
// Level: medium
// Author: @SerkinValery
// Date: 2024-07-22
// Tags: attack.credential-access, attack.t1528
// Description: Detects file access attempts to sensitive Microsoft teams files (leveldb, cookies) by an uncommon process.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((FileName contains "\\Microsoft\\Teams\\Cookies" or FileName contains "\\Microsoft\\Teams\\Local Storage\\leveldb")) and not ((action_process_image_path endswith "\\Microsoft\\Teams\\current\\Teams.exe")))
