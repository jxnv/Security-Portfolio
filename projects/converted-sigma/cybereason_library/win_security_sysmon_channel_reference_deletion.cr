// Title: Sysmon Channel Reference Deletion
// ID: 18beca67-ab3e-4ee3-ba7a-a46ca8d7d0cc
// Status: test
// Level: high
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2020-07-14
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Potential threat actor tampering with Sysmon manifest and eventually disabling it
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID == "4657" AND (ObjectName contains "WINEVT\\Publishers\\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" OR ObjectName contains "WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational") AND ObjectValueName == "Enabled" AND NewValue == "0") OR (EventID == "4663" AND (ObjectName contains "WINEVT\\Publishers\\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" OR ObjectName contains "WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational") AND AccessMask == "0x10000"))
