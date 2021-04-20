# ovhlog

## watchlog.py

`watchlog.py` is a basic python3 script that can be used to fetch Apache daily updated logs on an OVH account. Based on a regular check (by default 5 min) it write new logs to a daily file. Resume is support if logs were already partially written (append to log file, no overwriting). 

## usage

The help should be helpfull to you:

	usage: watchlog.py [-h] [--config CONFIG] [--destination-dir DESTINATION_DIR] [--verbose] [--printlog] [--silent]
	
	optional arguments:
	  -h, --help            show this help message and exit
	  --config CONFIG, -c CONFIG
	                        specify an alternate config file
	  --destination-dir DESTINATION_DIR, -d DESTINATION_DIR
	                        destination directory for logs
	  --verbose, -v         enable verbose printing to stderr
	  --printlog, -p        enable printing logs to stdout
	  --silent, -s          disable printing error to stderr

## config.json

The configuration is stored in a json file. Here is an example

	{
	  "cluster":"cluster123",
	  "vhost":"abcdefgh",
	  "user":"username",
	  "password":"yourpassword",
	  "refresh":"300"
	}

As this file contains credentials, you must carefully set the file permissions.

Note: you must first create a user account with a **strong** password in the stats and log section of you web hosting entry, see [OVH documentation (FR)](https://docs.ovh.com/fr/hosting/mutualise-consulter-les-statistiques-et-les-logs-de-mon-site/)

## Licence

This program is released under MIT licence.