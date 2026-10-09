// Title: Office Macro File Download
// ID: 0e29e3a7-1ad8-40aa-b691-9f82ecd33d66
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-01-23
// Tags: attack.initial-access, attack.t1566.001
// Description: Detects the creation of a new office macro files on the system via an application (browser, mail client).
// This can help identify potential malicious activity, such as the download of macro-enabled documents that could be used for exploitation.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_file_path endswith ".docm" or action_file_path endswith ".dotm" or action_file_path endswith ".xlsm" or action_file_path endswith ".xltm" or action_file_path endswith ".potm" or action_file_path endswith ".pptm")) or ((action_file_path contains ".docm:Zone" or action_file_path contains ".dotm:Zone" or action_file_path contains ".xlsm:Zone" or action_file_path contains ".xltm:Zone" or action_file_path contains ".potm:Zone" or action_file_path contains ".pptm:Zone"))) and ((action_process_image_path endswith "\\RuntimeBroker.exe" or action_process_image_path endswith "\\outlook.exe" or action_process_image_path endswith "\\thunderbird.exe" or action_process_image_path endswith "\\brave.exe" or action_process_image_path endswith "\\chrome.exe" or action_process_image_path endswith "\\firefox.exe" or action_process_image_path endswith "\\iexplore.exe" or action_process_image_path endswith "\\maxthon.exe" or action_process_image_path endswith "\\MicrosoftEdge.exe" or action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\msedgewebview2.exe" or action_process_image_path endswith "\\opera.exe" or action_process_image_path endswith "\\safari.exe" or action_process_image_path endswith "\\seamonkey.exe" or action_process_image_path endswith "\\vivaldi.exe" or action_process_image_path endswith "\\whale.exe")))
