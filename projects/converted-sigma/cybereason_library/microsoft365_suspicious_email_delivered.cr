// Title: Suspicious Email Delivered In Microsoft 365
// ID: 3569aefd-e535-4391-8c18-24bd01a21eaf
// Status: experimental
// Level: medium
// Author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
// Date: 2026-01-27
// Tags: attack.initial-access, attack.t1566.001, attack.t1566.002
// Description: Detects instances where an email, identified as malicious or suspicious by the Microsoft Defender for Office 365 (formerly ATP) engine, was delivered to a user's Inbox or Junk folder.
// It might indicate that a potential threat, such as a spearphishing attachment or links, has bypassed initial blocking mechanisms and reached an end-user, requiring further investigation and potential remediation.
// Converted by: Sigma Universal SIEM/EDR CLI

((Workload == "ThreatIntelligence" AND Operation == "TIMailData" AND Directionality == "Inbound") AND NOT ((DeliveryAction == "Blocked")))
