// Title: Antivirus - APT Malware Signature
// ID: 101a1877-2cf4-474d-abfd-7f6ac4788d1a
// Status: experimental
// Level: critical
// Author: Arnim Rupp (Nextron Systems)
// Date: 2026-06-15
// Tags: attack.execution, attack.t1203, attack.command-and-control, attack.t1219.002
// Description: Detects a highly relevant Antivirus alert that reports APT malware.
// This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Signature=regex("APT\\d") OR Signature=regex("ATK\\d") OR Signature=regex("UNC\\d") OR Signature=regex("UAC\\d"))) OR ((Signature: "*[APT]*" OR Signature: "*APT_*" OR Signature: "*APT-*" OR Signature: "*BackOrder*" OR Signature: "*BlindingCan*" OR Signature: "*Blizzard*" OR Signature: "*Chollima*" OR Signature: "*Cleaver*" OR Signature: "*Cobra*" OR Signature: "*DarkHotel*" OR Signature: "*Dragon*" OR Signature: "*DTrack*" OR Signature: "*Equation*" OR Signature: "*GiftedCrook*" OR Signature: "*GraphSteel*" OR Signature: "*GreyEnergy*" OR Signature: "*GEnergy*" OR Signature: "*GrimPlant*" OR Signature: "*Hydra*" OR Signature: "*Jackal*" OR Signature: "*Kitten*" OR Signature: "*Kimsuky*" OR Signature: "*Lazar*" OR Signature: "*LightRail*" OR Signature: "*Lotus*" OR Signature: "*Luminous*" OR Signature: "*LumiMoth*" OR Signature: "*Nimbus*" OR Signature: "*Manticore*" OR Signature: "*MiniBike*" OR Signature: "*MiniBrowse*" OR Signature: "*MiniBus*" OR Signature: "*MiniFast*" OR Signature: "*MiniJuke*" OR Signature: "*MiniUpdate*" OR Signature: "*MuddyWater*" OR Signature: "*NukeSped*" OR Signature: "*OilRig*" OR Signature: "*Panda*" OR Signature: "*Sandstorm*" OR Signature: "*SandWorm*" OR Signature: "*Seamonkey*" OR Signature: "*Sleet*" OR Signature: "*SlugResin*" OR Signature: "*SnailResin*" OR Signature: "*Snake*" OR Signature: "*Tempest*" OR Signature: "*Tsunami*" OR Signature: "*Turla*" OR Signature: "*Typhoon*" OR Signature: "*UAC_*" OR Signature: "*UAC-*" OR Signature: "*UNC_*" OR Signature: "*UNC-*" OR Signature: "*VinoSiren*" OR Signature: "*Winnti*")))
