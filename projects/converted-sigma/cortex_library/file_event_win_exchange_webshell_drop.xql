// Title: Suspicious ASPX File Drop by Exchange
// ID: bd1212e5-78da-431e-95fa-c58e3237a8e6
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), MSTI (query, idea)
// Date: 2022-10-01
// Tags: attack.persistence, attack.t1505.003
// Description: Detects suspicious file type dropped by an Exchange component in IIS into a suspicious folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\w3wp.exe" and action_process_image_command_line contains "MSExchange" and (action_file_path contains "FrontEnd\\HttpProxy\\" or action_file_path contains "\\inetpub\\wwwroot\\aspnet_client\\")) and ((action_file_path endswith ".aspx" or action_file_path endswith ".asp" or action_file_path endswith ".ashx")))
