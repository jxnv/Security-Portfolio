// Title: Access of Sudoers File Content
// ID: 0f79c4d2-4e1f-4683-9c36-b5469a665e06
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.reconnaissance, attack.t1592.004
// Description: Detects the execution of a text-based file access or inspection utilities to read the content of /etc/sudoers in order to potentially list all users that have sudo rights.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/cat" or action_process_image_path endswith "/ed" or action_process_image_path endswith "/egrep" or action_process_image_path endswith "/emacs" or action_process_image_path endswith "/fgrep" or action_process_image_path endswith "/grep" or action_process_image_path endswith "/head" or action_process_image_path endswith "/less" or action_process_image_path endswith "/more" or action_process_image_path endswith "/nano" or action_process_image_path endswith "/tail") and action_process_image_command_line contains " /etc/sudoers")
