// Title: Potential Crypto Mining Activity
// ID: 66c3b204-9f88-4d0a-a7f7-8a57d521ca55
// Status: stable
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-10-26
// Tags: attack.impact, attack.t1496
// Description: Detects command line parameters or strings often used by crypto miners
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " --cpu-priority=" or action_process_image_command_line contains "--donate-level=0" or action_process_image_command_line contains " -o pool." or action_process_image_command_line contains " --nicehash" or action_process_image_command_line contains " --algo=rx/0 " or action_process_image_command_line contains "stratum+tcp://" or action_process_image_command_line contains "stratum+udp://" or action_process_image_command_line contains "LS1kb25hdGUtbGV2ZWw9" or action_process_image_command_line contains "0tZG9uYXRlLWxldmVsP" or action_process_image_command_line contains "tLWRvbmF0ZS1sZXZlbD" or action_process_image_command_line contains "c3RyYXR1bSt0Y3A6Ly" or action_process_image_command_line contains "N0cmF0dW0rdGNwOi8v" or action_process_image_command_line contains "zdHJhdHVtK3RjcDovL" or action_process_image_command_line contains "c3RyYXR1bSt1ZHA6Ly" or action_process_image_command_line contains "N0cmF0dW0rdWRwOi8v" or action_process_image_command_line contains "zdHJhdHVtK3VkcDovL")) and not (((action_process_image_command_line contains " pool.c " or action_process_image_command_line contains " pool.o " or action_process_image_command_line contains "gcc -"))))
