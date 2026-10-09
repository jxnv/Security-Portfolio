// Title: LOLBIN Execution From Abnormal Drive
// ID: d4ca7c59-e9e4-42d8-bf57-91a776efcb87
// Status: test
// Level: medium
// Author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Angelo Violetti - SEC Consult '@angelo_violetti', Aaron Herman
// Date: 2022-01-25
// Tags: attack.stealth
// Description: Detects LOLBINs executing from an abnormal or uncommon drive such as a mounted ISO.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\cmstp.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\installutil.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_name = "CALC.EXE" or action_process_image_name = "CertUtil.exe" or action_process_image_name = "CMSTP.EXE" or action_process_image_name = "cscript.exe" or action_process_image_name = "installutil.exe" or action_process_image_name = "MSHTA.EXE" or action_process_image_name = "REGSVR32.EXE" or action_process_image_name = "RUNDLL32.EXE" or action_process_image_name = "wscript.exe"))) and not (((CurrentDirectory contains "C:\\") or (CurrentDirectory = "") or (CurrentDirectory = null))))
