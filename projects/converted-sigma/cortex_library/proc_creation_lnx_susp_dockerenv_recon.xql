// Title: Docker Container Discovery Via Dockerenv Listing
// ID: 11701de9-d5a5-44aa-8238-84252f131895
// Status: test
// Level: low
// Author: Seth Hanford
// Date: 2023-08-23
// Tags: attack.discovery, attack.t1082
// Description: Detects listing or file reading of ".dockerenv" which can be a sing of potential container discovery
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/cat" or action_process_image_path endswith "/dir" or action_process_image_path endswith "/find" or action_process_image_path endswith "/ls" or action_process_image_path endswith "/stat" or action_process_image_path endswith "/test" or action_process_image_path endswith "grep") and action_process_image_command_line endswith ".dockerenv")
