// Title: Suspicious Parent Double Extension File Execution
// ID: 5e6a80c8-2d45-4633-9ef4-fa2671a39c5c
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-06
// Tags: attack.stealth, attack.t1036.007
// Description: Detect execution of suspicious double extension files in ParentCommandLine
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith ".doc.lnk" or actor_process_image_path endswith ".docx.lnk" or actor_process_image_path endswith ".xls.lnk" or actor_process_image_path endswith ".xlsx.lnk" or actor_process_image_path endswith ".ppt.lnk" or actor_process_image_path endswith ".pptx.lnk" or actor_process_image_path endswith ".rtf.lnk" or actor_process_image_path endswith ".pdf.lnk" or actor_process_image_path endswith ".txt.lnk" or actor_process_image_path endswith ".doc.js" or actor_process_image_path endswith ".docx.js" or actor_process_image_path endswith ".xls.js" or actor_process_image_path endswith ".xlsx.js" or actor_process_image_path endswith ".ppt.js" or actor_process_image_path endswith ".pptx.js" or actor_process_image_path endswith ".rtf.js" or actor_process_image_path endswith ".pdf.js" or actor_process_image_path endswith ".txt.js")) or ((actor_process_command_line contains ".doc.lnk" or actor_process_command_line contains ".docx.lnk" or actor_process_command_line contains ".xls.lnk" or actor_process_command_line contains ".xlsx.lnk" or actor_process_command_line contains ".ppt.lnk" or actor_process_command_line contains ".pptx.lnk" or actor_process_command_line contains ".rtf.lnk" or actor_process_command_line contains ".pdf.lnk" or actor_process_command_line contains ".txt.lnk" or actor_process_command_line contains ".doc.js" or actor_process_command_line contains ".docx.js" or actor_process_command_line contains ".xls.js" or actor_process_command_line contains ".xlsx.js" or actor_process_command_line contains ".ppt.js" or actor_process_command_line contains ".pptx.js" or actor_process_command_line contains ".rtf.js" or actor_process_command_line contains ".pdf.js" or actor_process_command_line contains ".txt.js")))
