// Title: Remote File Download Via Desktopimgdownldr Utility
// ID: 214641c2-c579-4ecb-8427-0cf19df6842e
// Status: test
// Level: medium
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-27
// Tags: attack.command-and-control, attack.t1105
// Description: Detects the desktopimgdownldr utility being used to download a remote file. An adversary may use desktopimgdownldr to download arbitrary files as an alternative to certutil.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\desktopimgdownldr.exe" and actor_process_image_path endswith "\\desktopimgdownldr.exe" and action_process_image_command_line contains "/lockscreenurl:http")
