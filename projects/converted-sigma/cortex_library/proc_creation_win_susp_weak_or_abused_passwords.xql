// Title: Weak or Abused Passwords In CLI
// ID: 91edcfb1-2529-4ac2-9ecc-7617f895c7e4
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-14
// Tags: attack.execution, attack.stealth
// Description: Detects weak passwords or often abused passwords (seen used by threat actors) via the CLI.
// An example would be a threat actor creating a new user via the net command and providing the password inline
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "123456789" or action_process_image_command_line contains "123123qwE" or action_process_image_command_line contains "Asd123.aaaa" or action_process_image_command_line contains "Decryptme" or action_process_image_command_line contains "P@ssw0rd!" or action_process_image_command_line contains "Pass8080" or action_process_image_command_line contains "password123" or action_process_image_command_line contains "test@202"))
