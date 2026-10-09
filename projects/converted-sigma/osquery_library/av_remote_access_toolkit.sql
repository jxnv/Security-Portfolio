-- Title: Antivirus - Remote Access Tools Signature
-- ID: 97233998-3838-4581-88c6-f1d19d3993fb
-- Status: experimental
-- Level: critical
-- Author: Arnim Rupp (Nextron Systems)
-- Date: 2026-06-15
-- Tags: attack.execution, attack.t1203, attack.command-and-control, attack.t1219.002
-- Description: Detects a highly relevant Antivirus alert that reports a remote access tool.
-- This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Signature LIKE '%AgentB%' OR Signature LIKE '%AgentTesla%' OR Signature LIKE '%AMRat%' OR Signature LIKE '%Ammyy%' OR Signature LIKE '%AsyncRAT%' OR Signature LIKE '%Bandook%' OR Signature LIKE '%Bitrat%' OR Signature LIKE '%Bladabindi%' OR Signature LIKE '%Connectwise%' OR Signature LIKE '%CyberGate%' OR Signature LIKE '%DarkComet%' OR Signature LIKE '%DCrat%' OR Signature LIKE '%Delf%' OR Signature LIKE '%DokStorm%' OR Signature LIKE '%Egairtigado%' OR Signature LIKE '%Gh0st%' OR Signature LIKE '%Gorat%' OR Signature LIKE '%GodRat%' OR Signature LIKE '%Jalapeno%' OR Signature LIKE '%LummaC2%' OR Signature LIKE '%Minirat%' OR Signature LIKE '%Netwire%' OR Signature LIKE '%NanoCore%' OR Signature LIKE '%NJRat%' OR Signature LIKE '%Paralax%' OR Signature LIKE '%PlugX%' OR Signature LIKE '%Pulsar%' OR Signature LIKE '%Quasar%' OR Signature LIKE '%Remcos%' OR Signature LIKE '%Ravartar%' OR Signature LIKE '%RemoteAdmin%' OR Signature LIKE '%RemoteTool%' OR Signature LIKE '%revengeRAT%' OR Signature LIKE '%rokRAT%' OR Signature LIKE '%salatstealer%' OR Signature LIKE '%Salgorea%' OR Signature LIKE '%SmokedHam%' OR Signature LIKE '%TigerRat%' OR Signature LIKE '%Tzeebot%' OR Signature LIKE '%WarZone%' OR Signature LIKE '%VenomRAT%' OR Signature LIKE '%Vidar%' OR Signature LIKE '%Wirenet%' OR Signature LIKE '%XWorm%' OR Signature LIKE '%Zapchast%' OR Signature LIKE '%Zegost%'))
