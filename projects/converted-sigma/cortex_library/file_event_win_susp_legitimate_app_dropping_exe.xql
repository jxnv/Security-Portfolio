// Title: Legitimate Application Dropped Executable
// ID: f0540f7e-2db3-4432-b9e0-3965486744bc
// Status: test
// Level: high
// Author: frack113, Florian Roth (Nextron Systems)
// Date: 2022-08-21
// Tags: attack.stealth, attack.t1218
// Description: Detects LOLBINs and applications that should not legitimately drop executable or executable-equivalent files to disk.
// This may indicate malware staging, process injection, or abuse of a trusted binary for payload delivery.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\eqnedt32.exe" or action_process_image_path endswith "\\wordpad.exe" or action_process_image_path endswith "\\wordview.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\certoc.exe" or action_process_image_path endswith "\\CertReq.exe" or action_process_image_path endswith "\\Desktopimgdownldr.exe" or action_process_image_path endswith "\\esentutl.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\AcroRd32.exe" or action_process_image_path endswith "\\RdrCEF.exe" or action_process_image_path endswith "\\hh.exe" or action_process_image_path endswith "\\finger.exe") and (action_file_path endswith ".com" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".jar" or action_file_path endswith ".ocx" or action_file_path endswith ".pyc"))
