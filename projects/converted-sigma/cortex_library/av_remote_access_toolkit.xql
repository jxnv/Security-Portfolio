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

dataset = xdr_data | filter ((Signature contains "AgentB" or Signature contains "AgentTesla" or Signature contains "AMRat" or Signature contains "Ammyy" or Signature contains "AsyncRAT" or Signature contains "Bandook" or Signature contains "Bitrat" or Signature contains "Bladabindi" or Signature contains "Connectwise" or Signature contains "CyberGate" or Signature contains "DarkComet" or Signature contains "DCrat" or Signature contains "Delf" or Signature contains "DokStorm" or Signature contains "Egairtigado" or Signature contains "Gh0st" or Signature contains "Gorat" or Signature contains "GodRat" or Signature contains "Jalapeno" or Signature contains "LummaC2" or Signature contains "Minirat" or Signature contains "Netwire" or Signature contains "NanoCore" or Signature contains "NJRat" or Signature contains "Paralax" or Signature contains "PlugX" or Signature contains "Pulsar" or Signature contains "Quasar" or Signature contains "Remcos" or Signature contains "Ravartar" or Signature contains "RemoteAdmin" or Signature contains "RemoteTool" or Signature contains "revengeRAT" or Signature contains "rokRAT" or Signature contains "salatstealer" or Signature contains "Salgorea" or Signature contains "SmokedHam" or Signature contains "TigerRat" or Signature contains "Tzeebot" or Signature contains "WarZone" or Signature contains "VenomRAT" or Signature contains "Vidar" or Signature contains "Wirenet" or Signature contains "XWorm" or Signature contains "Zapchast" or Signature contains "Zegost"))
