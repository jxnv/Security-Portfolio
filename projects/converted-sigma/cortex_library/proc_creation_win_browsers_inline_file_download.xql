// Title: File Download From Browser Process Via Inline URL
// ID: 94771a71-ba41-4b6e-a757-b531372eaab6
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-01-11
// Tags: attack.command-and-control, attack.t1105
// Description: Detects execution of a browser process with a URL argument pointing to a file with a potentially interesting extension. This can be abused to download arbitrary files or to hide from the user for example by launching the browser in a minimized state.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line endswith ".7z" or action_process_image_command_line endswith ".dat" or action_process_image_command_line endswith ".dll" or action_process_image_command_line endswith ".exe" or action_process_image_command_line endswith ".hta" or action_process_image_command_line endswith ".ps1" or action_process_image_command_line endswith ".psm1" or action_process_image_command_line endswith ".txt" or action_process_image_command_line endswith ".vbe" or action_process_image_command_line endswith ".vbs" or action_process_image_command_line endswith ".zip")) or ((action_process_image_command_line contains ".7z\"" or action_process_image_command_line contains ".dat\"" or action_process_image_command_line contains ".dll\"" or action_process_image_command_line contains ".hta\"" or action_process_image_command_line contains ".ps1\"" or action_process_image_command_line contains ".psm1\"" or action_process_image_command_line contains ".txt\"" or action_process_image_command_line contains ".vbe\"" or action_process_image_command_line contains ".vbs\"" or action_process_image_command_line contains ".zip\""))) and (action_process_image_command_line contains "http") and ((action_process_image_path endswith "\\brave.exe" or action_process_image_path endswith "\\chrome.exe" or action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\opera.exe" or action_process_image_path endswith "\\vivaldi.exe")))
