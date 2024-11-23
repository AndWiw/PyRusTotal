Prerequisites: Python 3.11 and a VirusTotal account (for the API key)

Make sure that you open the terminal/command prompt and ensure you have the latest packages using the appropriate commands:
Windows: python -m pip install --upgrade pip
Mac/Linux: pip install --upgrade pip

Paste your VirusTotal API key that you get from https://www.virustotal.com/gui/my-apikey in indicated spot in the config.ini file

Run the main.py

You will be prompted to enter the location of the directory you wish to scan. The program is set to scan one file every 15 seconds to avoid any issues with VirusTotal's rate limits.

Once PyRusTotal is done, it will print out for each individual file if any matches on VirusTotal were found.

If you have any issues, don't hesitate to bring them up!
