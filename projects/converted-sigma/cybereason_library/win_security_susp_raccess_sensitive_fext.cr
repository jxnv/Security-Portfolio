// Title: Suspicious Access to Sensitive File Extensions
// ID: 91c945bc-2ad1-4799-a591-4d00198a1215
// Status: test
// Level: medium
// Author: Samir Bousseaden
// Date: 2019-04-03
// Tags: attack.collection, attack.t1039
// Description: Detects known sensitive file extensions accessed on a network share
// Converted by: Sigma Universal SIEM/EDR CLI

(EventID == "5145" AND (RelativeTargetName="*.bak" OR RelativeTargetName="*.dmp" OR RelativeTargetName="*.edb" OR RelativeTargetName="*.kirbi" OR RelativeTargetName="*.msg" OR RelativeTargetName="*.nsf" OR RelativeTargetName="*.nst" OR RelativeTargetName="*.oab" OR RelativeTargetName="*.ost" OR RelativeTargetName="*.pst" OR RelativeTargetName="*.rdp"))
