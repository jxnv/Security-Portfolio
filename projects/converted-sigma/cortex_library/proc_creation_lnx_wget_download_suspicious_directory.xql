// Title: Download File To Potentially Suspicious Directory Via Wget
// ID: cf610c15-ed71-46e1-bdf8-2bd1a99de6c4
// Status: test
// Level: medium
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-06-02
// Tags: attack.command-and-control, attack.t1105
// Description: Detects the use of wget to download content to a suspicious directory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/wget") and ((action_process_image_command_line ~= "\\s-O\\s") or (action_process_image_command_line contains "--output-document")) and (action_process_image_command_line contains "/tmp/"))
