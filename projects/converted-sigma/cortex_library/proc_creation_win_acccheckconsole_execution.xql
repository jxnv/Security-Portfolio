// Title: Potential DLL Injection Via AccCheckConsole
// ID: 0f6da907-5854-4be6-859a-e9958747b0aa
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-06
// Tags: attack.execution, detection.threat-hunting
// Description: Detects the execution "AccCheckConsole" a command-line tool for verifying the accessibility implementation of an application's UI.
// One of the tests that this checker can run are called "verification routine", which tests for things like Consistency, Navigation, etc.
// The tool allows a user to provide a DLL that can contain a custom "verification routine". An attacker can build such DLLs and pass it via the CLI, which would then be loaded in the context of the "AccCheckConsole" utility.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -hwnd" or action_process_image_command_line contains " -process " or action_process_image_command_line contains " -window ")) and ((action_process_image_path endswith "\\AccCheckConsole.exe") or (action_process_image_name = "AccCheckConsole.exe")))
