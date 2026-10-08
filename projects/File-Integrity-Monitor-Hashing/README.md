## Usage

1. Clone the repository.

2. Run the script using the following command:

   ```bash
   python file_monitoring_tool.py
Choose the function you would like to use:

A: Collect a new baseline of a folder of your choice.
B: Begin monitoring files with the existing baseline.
If you choose option A:

The tool will collect a new baseline by calculating the SHA256 hash of each file in the chosen folder.
The baseline will be stored in the baseline.txt file.
If baseline.txt already exists, it will be overwritten.
If you choose option B:

The tool will load the baseline from the baseline.txt file.
It will then start monitoring the files in the chosen folder for any changes.
If a new file is created, or if an existing file is modified or deleted, it will be reported.
Press 'Q' at any time to quit the program.

Configuration
The folder to be monitored can be configured by modifying the ./ActiveScanningFiles directory path in the code. Update the path accordingly to the folder you want to monitor.
Requirements
Python 3.x
