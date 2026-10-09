// Title: Antivirus - Ransomware Signature
// ID: 4c6ca276-d4d0-4a8c-9e4c-d69832f8671f
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems), Arnim Rupp
// Date: 2022-05-12
// Tags: attack.t1486, attack.impact
// Description: Detects a highly relevant Antivirus alert that reports ransomware.
// This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
// Converted by: Sigma Universal SIEM/EDR CLI

((Signature contains "Babuk" OR Signature contains "Babyk" OR Signature contains "BlackWorm" OR Signature contains "Chaos" OR Signature contains "Cobra" OR Signature contains "ContiCrypt" OR Signature contains "Crypter" OR Signature contains "Cryptes" OR Signature contains "Cryptor" OR Signature contains "CylanCrypt" OR Signature contains "DelShad" OR Signature contains "Destructor" OR Signature contains "Filecoder" OR Signature contains "GandCrab" OR Signature contains "GrandCrab" OR Signature contains "Haperlock" OR Signature contains "Hiddentear" OR Signature contains "HydraCrypt" OR Signature contains "Krypt" OR Signature contains "Lockbit" OR Signature contains "Locker" OR Signature contains "Mallox" OR Signature contains "Medusa" OR Signature contains "Phobos" OR Signature contains "Ransom" OR Signature contains "Rook" OR Signature contains "Ryuk" OR Signature contains "Ryzerlo" OR Signature contains "Stopcrypt" OR Signature contains "Tescrypt" OR Signature contains "TeslaCrypt" OR Signature contains "WannaCry" OR Signature contains "Xorist"))
