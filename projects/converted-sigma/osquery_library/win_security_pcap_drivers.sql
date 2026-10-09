-- Title: Windows Pcap Drivers
-- ID: 7b687634-ab20-11ea-bb37-0242ac130002
-- Status: test
-- Level: medium
-- Author: Cian Heasley
-- Date: 2020-06-10
-- Tags: attack.discovery, attack.credential-access, attack.t1040
-- Description: Detects Windows Pcap driver installation based on a list of associated .sys files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (EventID = '4697' AND (ServiceFileName LIKE '%pcap%' OR ServiceFileName LIKE '%npcap%' OR ServiceFileName LIKE '%npf%' OR ServiceFileName LIKE '%nm3%' OR ServiceFileName LIKE '%ndiscap%' OR ServiceFileName LIKE '%nmnt%' OR ServiceFileName LIKE '%windivert%' OR ServiceFileName LIKE '%USBPcap%' OR ServiceFileName LIKE '%pktmon%'))
