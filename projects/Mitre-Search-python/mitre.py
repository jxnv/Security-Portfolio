import requests

def display_mitre_attack_framework(attack_type, output_file=None):
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    output = ""

    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            attack_types = set()
            for technique in data["objects"]:
                if technique["type"] == "attack-pattern" and attack_type.lower() in technique['name'].lower():
                    output += f"Technique ID: {technique['external_references'][0]['external_id']}\n"
                    output += f"Technique Name: {technique['name']}\n"
                    output += f"Description: {technique['description']}\n"
                    output += "-----\n"

            if output_file:
                with open(output_file, 'w') as file:
                    file.write(output)
                print(f"Output written to file: {output_file}")
            else:
                print(output)
        else:
            print("Failed to retrieve the MITRE ATT&CK framework.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def display_attack_types():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            attack_types = set()
            for technique in data["objects"]:
                if technique["type"] == "attack-pattern":
                    attack_types.add(technique['name'].split(" - ")[0])

            print("Available Attack Types:")
            for index, attack_type in enumerate(attack_types, start=1):
                print(f"{index}. {attack_type}")
        else:
            print("Failed to retrieve the MITRE ATT&CK framework.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

display_attack_types()

selected_attack_type = input("Enter the number of the attack type to search for: ")

attack_types = []
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
try:
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        for technique in data["objects"]:
            if technique["type"] == "attack-pattern":
                attack_types.append(technique['name'].split(" - ")[0])
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")

if selected_attack_type.isdigit() and int(selected_attack_type) in range(1, len(attack_types) + 1):
    selected_attack_type = attack_types[int(selected_attack_type) - 1]
    output_file = input("Enter the output file name (leave blank to print to console): ")
    display_mitre_attack_framework(selected_attack_type, output_file)
else:
    print("Invalid selection. Please enter a valid number.")
