// Title: Suspicious Camera and Microphone Access
// ID: 62120148-6b7a-42be-8b91-271c04e281a3
// Status: test
// Level: high
// Author: Den Iuzvyk
// Date: 2020-06-07
// Tags: attack.collection, attack.t1125, attack.t1123
// Description: Detects Processes accessing the camera and microphone from suspicious folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\" and TargetObject contains "\\NonPackaged")) and ((TargetObject contains "microphone" or TargetObject contains "webcam")) and ((TargetObject contains ":#Windows#Temp#" or TargetObject contains ":#$Recycle.bin#" or TargetObject contains ":#Temp#" or TargetObject contains ":#Users#Public#" or TargetObject contains ":#Users#Default#" or TargetObject contains ":#Users#Desktop#")))
