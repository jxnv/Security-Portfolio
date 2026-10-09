// Title: Arbitrary File Download Via GfxDownloadWrapper.EXE
// ID: eee00933-a761-4cd0-be70-c42fe91731e7
// Status: test
// Level: medium
// Author: Victor Sergeev, oscd.community
// Date: 2020-10-09
// Tags: attack.command-and-control, attack.t1105
// Description: Detects execution of GfxDownloadWrapper.exe with a URL as an argument to download file.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\GfxDownloadWrapper.exe" and (action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://")) and not ((action_process_image_command_line contains "https://gameplayapi.intel.com/")))
