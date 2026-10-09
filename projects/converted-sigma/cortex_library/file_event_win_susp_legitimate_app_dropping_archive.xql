// Title: Legitimate Application Dropped Archive
// ID: 654fcc6d-840d-4844-9b07-2c3300e54a26
// Status: test
// Level: high
// Author: frack113, Florian Roth
// Date: 2022-08-21
// Tags: attack.stealth, attack.t1218
// Description: Detects programs on a Windows system that should not write an archive to disk
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\winword.exe" or action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\msaccess.exe" or action_process_image_path endswith "\\mspub.exe" or action_process_image_path endswith "\\eqnedt32.exe" or action_process_image_path endswith "\\visio.exe" or action_process_image_path endswith "\\wordpad.exe" or action_process_image_path endswith "\\wordview.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\certoc.exe" or action_process_image_path endswith "\\CertReq.exe" or action_process_image_path endswith "\\Desktopimgdownldr.exe" or action_process_image_path endswith "\\esentutl.exe" or action_process_image_path endswith "\\finger.exe" or action_process_image_path endswith "\\notepad.exe" or action_process_image_path endswith "\\AcroRd32.exe" or action_process_image_path endswith "\\RdrCEF.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\hh.exe") and (action_file_path endswith ".zip" or action_file_path endswith ".rar" or action_file_path endswith ".7z" or action_file_path endswith ".diagcab" or action_file_path endswith ".appx"))
