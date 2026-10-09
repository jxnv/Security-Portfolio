// Title: PUA - AdFind Suspicious Execution
// ID: 9a132afa-654e-11eb-ae93-0242ac130002
// Status: test
// Level: high
// Author: Janantha Marasinghe (https://github.com/blueteam0ps), FPT.EagleEye Team, omkar72, oscd.community
// Date: 2021-02-02
// Tags: attack.discovery, attack.t1018, attack.t1087.002, attack.t1482, attack.t1069.002, stp.1u
// Description: Detects AdFind execution with common flags seen used during attacks
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "domainlist" or action_process_image_command_line contains "trustdmp" or action_process_image_command_line contains "dcmodes" or action_process_image_command_line contains "adinfo" or action_process_image_command_line contains "-sc dclist" or action_process_image_command_line contains "computer_pwdnotreqd" or action_process_image_command_line contains "objectcategory=" or action_process_image_command_line contains "-subnets -f" or action_process_image_command_line contains "name=\"Domain Admins\"" or action_process_image_command_line contains "-sc u:" or action_process_image_command_line contains "domainncs" or action_process_image_command_line contains "dompol" or action_process_image_command_line contains " oudmp " or action_process_image_command_line contains "subnetdmp" or action_process_image_command_line contains "gpodmp" or action_process_image_command_line contains "fspdmp" or action_process_image_command_line contains "users_noexpire" or action_process_image_command_line contains "computers_active" or action_process_image_command_line contains "computers_pwdnotreqd"))
