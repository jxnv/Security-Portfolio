// Title: Monero Crypto Coin Mining Pool Lookup
// ID: b593fd50-7335-4682-a36c-4edcb68e4641
// Status: stable
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-10-24
// Tags: attack.impact, attack.t1496, attack.exfiltration, attack.t1567
// Description: Detects suspicious DNS queries to Monero mining pools
// Converted by: Sigma Universal SIEM/EDR CLI

((query contains "pool.minexmr.com" OR query contains "fr.minexmr.com" OR query contains "de.minexmr.com" OR query contains "sg.minexmr.com" OR query contains "ca.minexmr.com" OR query contains "us-west.minexmr.com" OR query contains "pool.supportxmr.com" OR query contains "mine.c3pool.com" OR query contains "xmr-eu1.nanopool.org" OR query contains "xmr-eu2.nanopool.org" OR query contains "xmr-us-east1.nanopool.org" OR query contains "xmr-us-west1.nanopool.org" OR query contains "xmr-asia1.nanopool.org" OR query contains "xmr-jp1.nanopool.org" OR query contains "xmr-au1.nanopool.org" OR query contains "xmr.2miners.com" OR query contains "xmr.hashcity.org" OR query contains "xmr.f2pool.com" OR query contains "xmrpool.eu" OR query contains "pool.hashvault.pro"))
