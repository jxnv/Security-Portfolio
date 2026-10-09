// Title: MMC Executing Files with Reversed Extensions Using RTLO Abuse
// ID: 9cfe4b27-1e56-48b4-b7a8-d46851c91a44
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-02-05
// Tags: attack.execution, attack.stealth, attack.t1204.002, attack.t1218.014, attack.t1036.002
// Description: Detects malicious behavior where the MMC utility (`mmc.exe`) executes files with reversed extensions caused by Right-to-Left Override (RLO) abuse, disguising them as document formats.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "cod.msc" or action_process_image_command_line contains "fdp.msc" or action_process_image_command_line contains "ftr.msc" or action_process_image_command_line contains "lmth.msc" or action_process_image_command_line contains "slx.msc" or action_process_image_command_line contains "tdo.msc" or action_process_image_command_line contains "xcod.msc" or action_process_image_command_line contains "xslx.msc" or action_process_image_command_line contains "xtpp.msc")) and ((action_process_image_path endswith "\\mmc.exe") or (action_process_image_name = "MMC.exe")))
