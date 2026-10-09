-- Title: Suspicious Camera and Microphone Access
-- ID: 62120148-6b7a-42be-8b91-271c04e281a3
-- Status: test
-- Level: high
-- Author: Den Iuzvyk
-- Date: 2020-06-07
-- Tags: attack.collection, attack.t1125, attack.t1123
-- Description: Detects Processes accessing the camera and microphone from suspicious folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\%' AND TargetObject LIKE '%\\NonPackaged%')) AND ((TargetObject LIKE '%microphone%' OR TargetObject LIKE '%webcam%')) AND ((TargetObject LIKE '%:#Windows#Temp#%' OR TargetObject LIKE '%:#$Recycle.bin#%' OR TargetObject LIKE '%:#Temp#%' OR TargetObject LIKE '%:#Users#Public#%' OR TargetObject LIKE '%:#Users#Default#%' OR TargetObject LIKE '%:#Users#Desktop#%')))
