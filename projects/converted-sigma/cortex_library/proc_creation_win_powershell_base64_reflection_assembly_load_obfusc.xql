// Title: Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call
// ID: 9c0295ce-d60d-40bd-bd74-84673b7592b1
// Status: test
// Level: high
// Author: pH-T (Nextron Systems)
// Date: 2022-03-01
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1027
// Description: Detects suspicious base64 encoded and obfuscated "LOAD" keyword used in .NET "reflection.assembly"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ" or action_process_image_command_line contains "oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA" or action_process_image_command_line contains "6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA" or action_process_image_command_line contains "OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ" or action_process_image_command_line contains "oAOgAoACIATABvACIAKwAiAGEAZAAiACkA" or action_process_image_command_line contains "6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA" or action_process_image_command_line contains "OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ" or action_process_image_command_line contains "oAOgAoACIATABvAGEAIgArACIAZAAiACkA" or action_process_image_command_line contains "6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA" or action_process_image_command_line contains "OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ" or action_process_image_command_line contains "oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA" or action_process_image_command_line contains "6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA" or action_process_image_command_line contains "OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ" or action_process_image_command_line contains "oAOgAoACcATABvACcAKwAnAGEAZAAnACkA" or action_process_image_command_line contains "6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA" or action_process_image_command_line contains "OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ" or action_process_image_command_line contains "oAOgAoACcATABvAGEAJwArACcAZAAnACkA" or action_process_image_command_line contains "6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA"))
