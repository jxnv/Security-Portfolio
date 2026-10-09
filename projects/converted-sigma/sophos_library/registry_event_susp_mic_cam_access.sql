-- Title: Suspicious Camera and Microphone Access
-- ID: 62120148-6b7a-42be-8b91-271c04e281a3
-- Status: test
-- Level: high
-- Author: Den Iuzvyk
-- Date: 2020-06-07
-- Tags: attack.collection, attack.t1125, attack.t1123
-- Description: Detects Processes accessing the camera and microphone from suspicious folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetObject ILIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\%' AND TargetObject ILIKE '%\\NonPackaged%')) AND ((TargetObject ILIKE '%microphone%' OR TargetObject ILIKE '%webcam%')) AND ((TargetObject ILIKE '%:#Windows#Temp#%' OR TargetObject ILIKE '%:#$Recycle.bin#%' OR TargetObject ILIKE '%:#Temp#%' OR TargetObject ILIKE '%:#Users#Public#%' OR TargetObject ILIKE '%:#Users#Default#%' OR TargetObject ILIKE '%:#Users#Desktop#%')))
