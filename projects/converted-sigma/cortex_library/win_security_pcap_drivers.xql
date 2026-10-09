// Title: Windows Pcap Drivers
// ID: 7b687634-ab20-11ea-bb37-0242ac130002
// Status: test
// Level: medium
// Author: Cian Heasley
// Date: 2020-06-10
// Tags: attack.discovery, attack.credential-access, attack.t1040
// Description: Detects Windows Pcap driver installation based on a list of associated .sys files.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 4697 and (ServiceFileName contains "pcap" or ServiceFileName contains "npcap" or ServiceFileName contains "npf" or ServiceFileName contains "nm3" or ServiceFileName contains "ndiscap" or ServiceFileName contains "nmnt" or ServiceFileName contains "windivert" or ServiceFileName contains "USBPcap" or ServiceFileName contains "pktmon"))
