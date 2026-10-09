-- Title: Suspicious Obfuscated PowerShell Code
-- ID: 8d01b53f-456f-48ee-90f6-bc28e67d4e35
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-07-11
-- Tags: attack.stealth
-- Description: Detects suspicious UTF16 and base64 encoded and often obfuscated PowerShell code often used in command lines
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%IAAtAGIAeABvAHIAIAAwAHgA%' OR CommandLine LIKE '%AALQBiAHgAbwByACAAMAB4A%' OR CommandLine LIKE '%gAC0AYgB4AG8AcgAgADAAeA%' OR CommandLine LIKE '%AC4ASQBuAHYAbwBrAGUAKAApACAAfAAg%' OR CommandLine LIKE '%AuAEkAbgB2AG8AawBlACgAKQAgAHwAI%' OR CommandLine LIKE '%ALgBJAG4AdgBvAGsAZQAoACkAIAB8AC%' OR CommandLine LIKE '%AHsAMQB9AHsAMAB9ACIAIAAtAGYAI%' OR CommandLine LIKE '%B7ADEAfQB7ADAAfQAiACAALQBmAC%' OR CommandLine LIKE '%AewAxAH0AewAwAH0AIgAgAC0AZgAg%' OR CommandLine LIKE '%AHsAMAB9AHsAMwB9ACIAIAAtAGYAI%' OR CommandLine LIKE '%B7ADAAfQB7ADMAfQAiACAALQBmAC%' OR CommandLine LIKE '%AewAwAH0AewAzAH0AIgAgAC0AZgAg%' OR CommandLine LIKE '%AHsAMgB9AHsAMAB9ACIAIAAtAGYAI%' OR CommandLine LIKE '%B7ADIAfQB7ADAAfQAiACAALQBmAC%' OR CommandLine LIKE '%AewAyAH0AewAwAH0AIgAgAC0AZgAg%' OR CommandLine LIKE '%AHsAMQB9AHsAMAB9ACcAIAAtAGYAI%' OR CommandLine LIKE '%B7ADEAfQB7ADAAfQAnACAALQBmAC%' OR CommandLine LIKE '%AewAxAH0AewAwAH0AJwAgAC0AZgAg%' OR CommandLine LIKE '%AHsAMAB9AHsAMwB9ACcAIAAtAGYAI%' OR CommandLine LIKE '%B7ADAAfQB7ADMAfQAnACAALQBmAC%' OR CommandLine LIKE '%AewAwAH0AewAzAH0AJwAgAC0AZgAg%' OR CommandLine LIKE '%AHsAMgB9AHsAMAB9ACcAIAAtAGYAI%' OR CommandLine LIKE '%B7ADIAfQB7ADAAfQAnACAALQBmAC%' OR CommandLine LIKE '%AewAyAH0AewAwAH0AJwAgAC0AZgAg%'))
