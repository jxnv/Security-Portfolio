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

((TargetFilename="*.evtx") AND NOT (((TargetFilename="C:\\ProgramData\\Microsoft\\Windows\\Containers\\BaseImages\\*" AND TargetFilename="*\\Windows\\System32\\winevt\\Logs\\") OR (TargetFilename="C:\\Windows\\System32\\winevt\\Logs\\*"))))
