// Title: Shell Execution Of Process Located In Tmp Directory
// ID: 2fade0b6-7423-4835-9d4f-335b39b83867
// Status: test
// Level: high
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-06-02
// Tags: attack.execution
// Description: Detects execution of shells from a parent process located in a temporary (/tmp) directory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path startswith "/tmp/" and (action_process_image_path endswith "/bash" or action_process_image_path endswith "/csh" or action_process_image_path endswith "/dash" or action_process_image_path endswith "/fish" or action_process_image_path endswith "/ksh" or action_process_image_path endswith "/sh" or action_process_image_path endswith "/zsh"))
