// Title: System Information Discovery Using Ioreg
// ID: 2d5e7a8b-f484-4a24-945d-7f0efd52eab0
// Status: test
// Level: medium
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-12-20
// Tags: attack.discovery, attack.t1082
// Description: Detects the use of "ioreg" which will show I/O Kit registry information.
// This process is used for system information discovery.
// It has been observed in-the-wild by calling this process directly or using bash and grep to look for specific strings.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-l" or action_process_image_command_line contains "-c")) and ((action_process_image_command_line contains "AppleAHCIDiskDriver" or action_process_image_command_line contains "IOPlatformExpertDevice" or action_process_image_command_line contains "Oracle" or action_process_image_command_line contains "Parallels" or action_process_image_command_line contains "USB Vendor Name" or action_process_image_command_line contains "VirtualBox" or action_process_image_command_line contains "VMware")) and ((action_process_image_path endswith "/ioreg") or (action_process_image_command_line contains "ioreg")))
