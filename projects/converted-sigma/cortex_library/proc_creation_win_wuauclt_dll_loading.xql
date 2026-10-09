// Title: Proxy Execution Via Wuauclt.EXE
// ID: af77cf95-c469-471c-b6a0-946c685c4798
// Status: test
// Level: high
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), Florian Roth (Nextron Systems), Sreeman, FPT.EagleEye Team
// Date: 2020-10-12
// Tags: attack.stealth, attack.t1218, attack.execution
// Description: Detects the use of the Windows Update Client binary (wuauclt.exe) for proxy execution.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "UpdateDeploymentProvider" and action_process_image_command_line contains "RunHandlerComServer")) and ((action_process_image_path endswith "\\wuauclt.exe") or (action_process_image_name = "wuauclt.exe"))) and not (((action_process_image_command_line contains " /UpdateDeploymentProvider UpdateDeploymentProvider.dll ") or ((action_process_image_command_line contains ":\\Windows\\UUS\\Packages\\Preview\\amd64\\updatedeploy.dll /ClassId" or action_process_image_command_line contains ":\\Windows\\UUS\\amd64\\UpdateDeploy.dll /ClassId")) or ((action_process_image_command_line contains ":\\Windows\\WinSxS\\" and action_process_image_command_line contains "\\UpdateDeploy.dll /ClassId ")) or (action_process_image_command_line contains " wuaueng.dll "))))
