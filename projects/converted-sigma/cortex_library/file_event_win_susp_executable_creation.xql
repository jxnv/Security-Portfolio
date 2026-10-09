// Title: Suspicious Executable File Creation
// ID: 74babdd6-a758-4549-9632-26535279e654
// Status: test
// Level: high
// Author: frack113
// Date: 2022-09-05
// Tags: attack.stealth, attack.t1564
// Description: Detect creation of suspicious executable file names.
// Some strings look for suspicious file extensions, others look for filenames that exploit unquoted service paths.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith ":\\$Recycle.Bin.exe" or action_file_path endswith ":\\Documents and Settings.exe" or action_file_path endswith ":\\MSOCache.exe" or action_file_path endswith ":\\PerfLogs.exe" or action_file_path endswith ":\\Recovery.exe" or action_file_path endswith ".bat.exe" or action_file_path endswith ".sys.exe"))
