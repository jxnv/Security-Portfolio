-- Title: Antivirus - APT Malware Signature
-- ID: 101a1877-2cf4-474d-abfd-7f6ac4788d1a
-- Status: experimental
-- Level: critical
-- Author: Arnim Rupp (Nextron Systems)
-- Date: 2026-06-15
-- Tags: attack.execution, attack.t1203, attack.command-and-control, attack.t1219.002
-- Description: Detects a highly relevant Antivirus alert that reports APT malware.
-- This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((Signature=regex("APT\\d") OR Signature=regex("ATK\\d") OR Signature=regex("UNC\\d") OR Signature=regex("UAC\\d"))) OR ((Signature LIKE '%[APT]%' OR Signature LIKE '%APT_%' OR Signature LIKE '%APT-%' OR Signature LIKE '%BackOrder%' OR Signature LIKE '%BlindingCan%' OR Signature LIKE '%Blizzard%' OR Signature LIKE '%Chollima%' OR Signature LIKE '%Cleaver%' OR Signature LIKE '%Cobra%' OR Signature LIKE '%DarkHotel%' OR Signature LIKE '%Dragon%' OR Signature LIKE '%DTrack%' OR Signature LIKE '%Equation%' OR Signature LIKE '%GiftedCrook%' OR Signature LIKE '%GraphSteel%' OR Signature LIKE '%GreyEnergy%' OR Signature LIKE '%GEnergy%' OR Signature LIKE '%GrimPlant%' OR Signature LIKE '%Hydra%' OR Signature LIKE '%Jackal%' OR Signature LIKE '%Kitten%' OR Signature LIKE '%Kimsuky%' OR Signature LIKE '%Lazar%' OR Signature LIKE '%LightRail%' OR Signature LIKE '%Lotus%' OR Signature LIKE '%Luminous%' OR Signature LIKE '%LumiMoth%' OR Signature LIKE '%Nimbus%' OR Signature LIKE '%Manticore%' OR Signature LIKE '%MiniBike%' OR Signature LIKE '%MiniBrowse%' OR Signature LIKE '%MiniBus%' OR Signature LIKE '%MiniFast%' OR Signature LIKE '%MiniJuke%' OR Signature LIKE '%MiniUpdate%' OR Signature LIKE '%MuddyWater%' OR Signature LIKE '%NukeSped%' OR Signature LIKE '%OilRig%' OR Signature LIKE '%Panda%' OR Signature LIKE '%Sandstorm%' OR Signature LIKE '%SandWorm%' OR Signature LIKE '%Seamonkey%' OR Signature LIKE '%Sleet%' OR Signature LIKE '%SlugResin%' OR Signature LIKE '%SnailResin%' OR Signature LIKE '%Snake%' OR Signature LIKE '%Tempest%' OR Signature LIKE '%Tsunami%' OR Signature LIKE '%Turla%' OR Signature LIKE '%Typhoon%' OR Signature LIKE '%UAC_%' OR Signature LIKE '%UAC-%' OR Signature LIKE '%UNC_%' OR Signature LIKE '%UNC-%' OR Signature LIKE '%VinoSiren%' OR Signature LIKE '%Winnti%')))
