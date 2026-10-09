// Title: Suspicious Where Execution
// ID: 725a9768-0f5e-4cb3-aec2-bc5719c6831a
// Status: test
// Level: low
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-12-13
// Tags: attack.discovery, attack.t1217
// Description: Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
// Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
// internal network resources such as servers, tools/dashboards, or other related infrastructure.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\where.exe") or (action_process_image_name = "where.exe")) and ((action_process_image_command_line contains "places.sqlite" or action_process_image_command_line contains "cookies.sqlite" or action_process_image_command_line contains "formhistory.sqlite" or action_process_image_command_line contains "logins.json" or action_process_image_command_line contains "key4.db" or action_process_image_command_line contains "key3.db" or action_process_image_command_line contains "sessionstore.jsonlz4" or action_process_image_command_line contains "History" or action_process_image_command_line contains "Bookmarks" or action_process_image_command_line contains "Cookies" or action_process_image_command_line contains "Login Data")))
