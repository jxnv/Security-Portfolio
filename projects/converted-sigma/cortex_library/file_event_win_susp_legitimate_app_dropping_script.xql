// Title: Legitimate Application Dropped Script
// ID: 7d604714-e071-49ff-8726-edeb95a70679
// Status: test
// Level: high
// Author: frack113, Florian Roth (Nextron Systems)
// Date: 2022-08-21
// Tags: attack.stealth, attack.t1218
// Description: Detects LOLBINs and applications that should not legitimately drop script files to disk.
// This may indicate malware staging or abuse of a trusted binary for script-based code execution.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\eqnedt32.exe" or action_process_image_path endswith "\\wordpad.exe" or action_process_image_path endswith "\\wordview.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\certoc.exe" or action_process_image_path endswith "\\CertReq.exe" or action_process_image_path endswith "\\Desktopimgdownldr.exe" or action_process_image_path endswith "\\esentutl.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\AcroRd32.exe" or action_process_image_path endswith "\\RdrCEF.exe" or action_process_image_path endswith "\\hh.exe" or action_process_image_path endswith "\\finger.exe") and (action_file_path endswith ".bat" or action_file_path endswith ".chm" or action_file_path endswith ".csproj" or action_file_path endswith ".hta" or action_file_path endswith ".js" or action_file_path endswith ".jse" or action_file_path endswith ".proj" or action_file_path endswith ".ps1" or action_file_path endswith ".py" or action_file_path endswith ".scf" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs" or action_file_path endswith ".wsf" or action_file_path endswith ".wsh")) and not ((action_process_image_path endswith "\\mshta.exe" and action_file_path endswith ".hta")))
