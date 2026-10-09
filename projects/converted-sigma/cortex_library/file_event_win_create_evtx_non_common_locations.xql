// Title: EVTX Created In Uncommon Location
// ID: 65236ec7-ace0-4f0c-82fd-737b04fd4dcb
// Status: test
// Level: medium
// Author: D3F7A5105
// Date: 2023-01-02
// Tags: attack.defense-impairment, attack.t1685.001
// Description: Detects the creation of new files with the ".evtx" extension in non-common or non-standard location.
// This could indicate tampering with default EVTX locations in order to evade security controls or simply exfiltration of event log to search for sensitive information within.
// Note that backup software and legitimate administrator might perform similar actions during troubleshooting.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith ".evtx") and not (((action_file_path startswith "C:\\ProgramData\\Microsoft\\Windows\\Containers\\BaseImages\\" and action_file_path endswith "\\Windows\\System32\\winevt\\Logs\\") or (action_file_path startswith "C:\\Windows\\System32\\winevt\\Logs\\"))))
