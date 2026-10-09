// Title: Github Self-Hosted Runner Execution
// ID: 5bac7a56-da88-4c27-922e-c81e113b20cb
// Status: test
// Level: medium
// Author: Daniel Koifman (KoifSec)
// Date: 2025-11-29
// Tags: attack.command-and-control, attack.t1102.002, attack.t1071
// Description: Detects GitHub self-hosted runners executing workflows on local infrastructure that could be abused for persistence and code execution.
// Shai-Hulud is an npm supply chain worm targeting CI/CD environments.
// It installs runners on compromised systems to maintain access after credential theft, leveraging their access to secrets and internal networks.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "spawnclient") and ((action_process_image_path endswith "\\Runner.Worker.exe") or (action_process_image_name = "Runner.Worker.dll"))) or (((action_process_image_command_line contains "run" or action_process_image_command_line contains "configure")) and ((action_process_image_path endswith "\\Runner.Listener.exe") or (action_process_image_name = "Runner.Listener.dll"))))
