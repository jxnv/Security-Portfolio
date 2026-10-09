-- Title: Suspicious Run Key from Download
-- ID: 9c5037d1-c568-49b3-88c7-9846a5bdc2be
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Swachchhanda Shrawan Poude (Nextron Systems)
-- Date: 2019-10-01
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Image LIKE '%\\AppData\\Local\\Packages\\Microsoft.Outlook_%' OR Image LIKE '%\\AppData\\Local\\Microsoft\\Olk\\Attachments\\%' OR Image LIKE '%\\Downloads\\%' OR Image LIKE '%\\Temporary Internet Files\\Content.Outlook\\%' OR Image LIKE '%\\Local Settings\\Temporary Internet Files\\%') AND (TargetObject LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR TargetObject LIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR TargetObject LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%'))
