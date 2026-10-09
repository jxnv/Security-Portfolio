// Title: Registry Manipulation via WMI Stdregprov
// ID: c453ab7a-1f5c-4716-a3b4-dea8135fb43a
// Status: experimental
// Level: medium
// Author: Daniel Koifman (KoifSec)
// Date: 2025-07-30
// Tags: attack.execution, attack.t1047, attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects the usage of wmic.exe to modify Windows registry via the WMI StdRegProv class write methods (CreateKey, DeleteKey, SetStringValue, etc.).
// This behaviour could be potentially suspicious because it uses an alternative method to modify registry keys instead of legitimate registry tools like reg.exe or regedit.exe.
// Attackers specifically choose this technique to evade detection and bypass security monitoring focused on traditional registry modification commands.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "stdregprov" and action_process_image_command_line contains "call") and (action_process_image_command_line contains "CreateKey" or action_process_image_command_line contains "DeleteKey" or action_process_image_command_line contains "DeleteValue" or action_process_image_command_line contains "SetBinaryValue" or action_process_image_command_line contains "SetDWORDValue" or action_process_image_command_line contains "SetExpandedStringValue" or action_process_image_command_line contains "SetMultiStringValue" or action_process_image_command_line contains "SetQWORDValue" or action_process_image_command_line contains "SetSecurityDescriptor" or action_process_image_command_line contains "SetStringValue")) and ((action_process_image_path endswith "\\wmic.exe") or (action_process_image_name = "wmic.exe")))
