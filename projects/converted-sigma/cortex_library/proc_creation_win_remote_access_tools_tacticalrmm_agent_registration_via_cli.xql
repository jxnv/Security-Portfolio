// Title: Remote Access Tool - TacticalRMM Agent Registration to Potentially Attacker-Controlled Server
// ID: 2db93a3f-3249-4f73-9e68-0e77a0f8ae7e
// Status: experimental
// Level: medium
// Author: Ahmed Nosir (@egycondor)
// Date: 2025-05-29
// Tags: attack.command-and-control, attack.t1219, attack.t1105
// Description: Detects TacticalRMM agent installations where the --api, --auth, and related flags are used on the command line.
// These parameters configure the agent to connect to a specific RMM server with authentication, client ID, and site ID.
// This technique could indicate a threat actor attempting to register the agent with an attacker-controlled RMM infrastructure silently.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path contains "\\TacticalAgent\\tacticalrmm.exe" and (action_process_image_command_line contains "--api" and action_process_image_command_line contains "--auth" and action_process_image_command_line contains "--client-id" and action_process_image_command_line contains "--site-id" and action_process_image_command_line contains "--agent-type"))
