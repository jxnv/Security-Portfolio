// Title: Antivirus - Remote Access Tools Signature
// ID: 97233998-3838-4581-88c6-f1d19d3993fb
// Status: experimental
// Level: critical
// Author: Arnim Rupp (Nextron Systems)
// Date: 2026-06-15
// Tags: attack.execution, attack.t1203, attack.command-and-control, attack.t1219.002
// Description: Detects a highly relevant Antivirus alert that reports a remote access tool.
// This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
// Converted by: Sigma Universal SIEM/EDR CLI

((Signature contains "AgentB" OR Signature contains "AgentTesla" OR Signature contains "AMRat" OR Signature contains "Ammyy" OR Signature contains "AsyncRAT" OR Signature contains "Bandook" OR Signature contains "Bitrat" OR Signature contains "Bladabindi" OR Signature contains "Connectwise" OR Signature contains "CyberGate" OR Signature contains "DarkComet" OR Signature contains "DCrat" OR Signature contains "Delf" OR Signature contains "DokStorm" OR Signature contains "Egairtigado" OR Signature contains "Gh0st" OR Signature contains "Gorat" OR Signature contains "GodRat" OR Signature contains "Jalapeno" OR Signature contains "LummaC2" OR Signature contains "Minirat" OR Signature contains "Netwire" OR Signature contains "NanoCore" OR Signature contains "NJRat" OR Signature contains "Paralax" OR Signature contains "PlugX" OR Signature contains "Pulsar" OR Signature contains "Quasar" OR Signature contains "Remcos" OR Signature contains "Ravartar" OR Signature contains "RemoteAdmin" OR Signature contains "RemoteTool" OR Signature contains "revengeRAT" OR Signature contains "rokRAT" OR Signature contains "salatstealer" OR Signature contains "Salgorea" OR Signature contains "SmokedHam" OR Signature contains "TigerRat" OR Signature contains "Tzeebot" OR Signature contains "WarZone" OR Signature contains "VenomRAT" OR Signature contains "Vidar" OR Signature contains "Wirenet" OR Signature contains "XWorm" OR Signature contains "Zapchast" OR Signature contains "Zegost"))
