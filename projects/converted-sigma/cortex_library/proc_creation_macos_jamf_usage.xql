// Title: JAMF MDM Execution
// ID: be2e3a5c-9cc7-4d02-842a-68e9cb26ec49
// Status: test
// Level: low
// Author: Jay Pandit
// Date: 2023-08-22
// Tags: attack.execution
// Description: Detects execution of the "jamf" binary to create user accounts and run commands. For example, the binary can be abused by attackers on the system in order to bypass security controls or remove application control polices.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/jamf" and (action_process_image_command_line contains "createAccount" or action_process_image_command_line contains "manage" or action_process_image_command_line contains "removeFramework" or action_process_image_command_line contains "removeMdmProfile" or action_process_image_command_line contains "resetPassword" or action_process_image_command_line contains "setComputerName"))
