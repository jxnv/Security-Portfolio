// Title: Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location
// ID: 416bc4a2-7217-4519-8dc7-c3271817f1d5
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-11-27
// Tags: attack.credential-access, attack.defense-impairment, attack.t1003, attack.t1685
// Description: Detects loading of dbgcore.dll or dbghelp.dll from uncommon locations such as user directories.
// These DLLs contain the MiniDumpWriteDump function, which can be abused for credential dumping purposes or in some cases for evading EDR/AV detection by suspending processes.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ImageLoaded endswith "\\dbgcore.dll" or ImageLoaded endswith "\\dbghelp.dll")) and ((action_process_image_path contains ":\\Perflogs\\" or action_process_image_path contains ":\\Temp\\" or action_process_image_path contains ":\\Users\\Public\\" or action_process_image_path contains "\\$Recycle.Bin\\" or action_process_image_path contains "\\Contacts\\" or action_process_image_path contains "\\Documents\\" or action_process_image_path contains "\\Favorites\\" or action_process_image_path contains "\\Favourites\\" or action_process_image_path contains "\\inetpub\\wwwroot\\" or action_process_image_path contains "\\Music\\" or action_process_image_path contains "\\Pictures\\" or action_process_image_path contains "\\Start Menu\\Programs\\Startup\\" or action_process_image_path contains "\\Users\\Default\\" or action_process_image_path contains "\\Videos\\")))
