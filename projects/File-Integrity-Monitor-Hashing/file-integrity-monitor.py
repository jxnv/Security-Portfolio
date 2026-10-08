import os
import hashlib
import time

# Ask user which function they would like to use

print("Which function would you like to use?")

print("A: Collect new baseline of folder of your choice?")

print("B: Begin monitoring files with new baseline")

# ask user to input their choice

while True:
    user_choice = input("Enter your choice (A or B): ")
    
    user_choice = user_choice.upper()
    
    if user_choice == 'A' or user_choice == 'B':
        break  # Exit the loop if the choice is valid
    elif user_choice == 'Q':
        print('Quitting')
        quit()
    else:
        print("Your choice must be either A or B. Please try again. Press Q to exit program")

# Continue with the rest of the program

if user_choice == 'A':
    print("You chose to collect a new baseline")
    
    if os.path.exists("baseline.txt"):
        os.remove("baseline.txt")
     
    files = os.listdir('./ActiveScanningFiles')
    
    for file in files:
        file_path = os.path.join("./ActiveScanningFiles", file) #change directory of scanned folder here
        with open(file_path, "rb") as f:
            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
        with open("baseline.txt", "a") as baseline_file:
            baseline_file.write(f"{file_path}|{file_hash}\n")
         
elif user_choice == 'B':
    print("Beginning monitoring files now")

    # Load file and hash from baseline.txt and store them via dictionary
    file_hash_dictionary = {}
    with open("baseline.txt", "r") as baseline_file:
        file_paths_and_hashes = baseline_file.readlines()
        for line in file_paths_and_hashes:
            file_path, file_hash = line.strip().split("|") 
            file_hash_dictionary[file_path] = file_hash

    # Monitoring section of the code
    while True:
        time.sleep(1)
        files = os.listdir("./ActiveScanningFiles") #change directory of scanned folder here
        for file in files:
            file_path = os.path.join("./ActiveScanningFiles", file) #change directory of scanned folder here
            with open(file_path, "rb") as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()

            # Notify if a new file has been created
            if file_path not in file_hash_dictionary:
                print(f"{file_path} has been created!")

            # Notify if a file has been changed
            elif file_hash_dictionary[file_path] != file_hash:
                print(f"{file_path} has been changed!")

        # Notify if a baseline file has been deleted
        for key in list(file_hash_dictionary.keys()):
            if not os.path.exists(key):
                print(f"{key} has been deleted!")
                del file_hash_dictionary[key]

