// Title: Processes Accessing the Microphone and Webcam
// ID: 8cd538a4-62d5-4e83-810b-12d41e428d6e
// Status: test
// Level: medium
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2020-06-07
// Tags: attack.collection, attack.t1123
// Description: Potential adversaries accessing the microphone and webcam in an endpoint.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4657 or EventID = 4656 or EventID = 4663) and (ObjectName contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged" or ObjectName contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged"))
