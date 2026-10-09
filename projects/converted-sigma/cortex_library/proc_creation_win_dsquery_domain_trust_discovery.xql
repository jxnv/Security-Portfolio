// Title: Domain Trust Discovery Via Dsquery
// ID: 3bad990e-4848-4a78-9530-b427d854aac0
// Status: test
// Level: medium
// Author: E.M. Anhaus, Tony Lambert, oscd.community, omkar72
// Date: 2019-10-24
// Tags: attack.discovery, attack.t1482
// Description: Detects execution of "dsquery.exe" for domain trust discovery
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "trustedDomain") and ((action_process_image_path endswith "\\dsquery.exe") or (action_process_image_name = "dsquery.exe")))
