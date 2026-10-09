-- Title: Antivirus - Ransomware Signature
-- ID: 4c6ca276-d4d0-4a8c-9e4c-d69832f8671f
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems), Arnim Rupp
-- Date: 2022-05-12
-- Tags: attack.t1486, attack.impact
-- Description: Detects a highly relevant Antivirus alert that reports ransomware.
-- This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Signature LIKE '%Babuk%' OR Signature LIKE '%Babyk%' OR Signature LIKE '%BlackWorm%' OR Signature LIKE '%Chaos%' OR Signature LIKE '%Cobra%' OR Signature LIKE '%ContiCrypt%' OR Signature LIKE '%Crypter%' OR Signature LIKE '%Cryptes%' OR Signature LIKE '%Cryptor%' OR Signature LIKE '%CylanCrypt%' OR Signature LIKE '%DelShad%' OR Signature LIKE '%Destructor%' OR Signature LIKE '%Filecoder%' OR Signature LIKE '%GandCrab%' OR Signature LIKE '%GrandCrab%' OR Signature LIKE '%Haperlock%' OR Signature LIKE '%Hiddentear%' OR Signature LIKE '%HydraCrypt%' OR Signature LIKE '%Krypt%' OR Signature LIKE '%Lockbit%' OR Signature LIKE '%Locker%' OR Signature LIKE '%Mallox%' OR Signature LIKE '%Medusa%' OR Signature LIKE '%Phobos%' OR Signature LIKE '%Ransom%' OR Signature LIKE '%Rook%' OR Signature LIKE '%Ryuk%' OR Signature LIKE '%Ryzerlo%' OR Signature LIKE '%Stopcrypt%' OR Signature LIKE '%Tescrypt%' OR Signature LIKE '%TeslaCrypt%' OR Signature LIKE '%WannaCry%' OR Signature LIKE '%Xorist%'))
