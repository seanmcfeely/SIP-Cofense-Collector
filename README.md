# SIP Cofense Collector

This tool consumes json reports dropped from Cofenses's `phishme_intelligence` json integration and maps indicators to SIP.

This tool was written quickly for a PoC/trial integration. I will refer to it as SIP_CC in this README.

# Quick overview

+ Supports a configured "max indicators per day" that can be set. Use this to scale at your comfort level.

+ "archives" reports after processing (just moves them to a different directory)

+ Keeps track of threat names and descriptions (mostly for curiosity)

+ Tags indicators respective to the report context it came from, as well as, where each indicator belongs in the attack.

## Set up

Example HOME dir, and config paths::

    HOME: "/opt/cofenseCollector"
    Cofense config: HOME + "etc/cofense_config.ini"
    SIP_CC: HOME + "etc/config.ini"

An example `config.ini` is included. You can pull a copy of the `cofense_config.ini` from Cofense's documentation (if you have access).

### Cofense - phishme_intelligence

First, follow their documentation to put your authentication details in the right spot.

Second, turn on the json integration for `phishme_intelligence` with `multiple_file_use` set. The `multiple_file_location` should be the directory you want new reports to land in.

The final config sections should look like this (not counting auth):
```
[integration_raw_json]
use = True
append_file_use = False
append_file_location = 
multiple_file_use = True
multiple_file_location = /opt/cofenseCollector/incoming
multiple_file_split_by_date = True

[pm_format]
cef = False
json = True
stix = False
```

Third, turn on `brand_intelligence` to get the good stuff.

```
[pm_product]
intelligence = True
brand_intelligence = True
```

### Set up SIP

https://github.com/ace-ecosystem/SIP

Help us pick SIP development back up ;-) 

### Set up the SIP Cofense Collector (this tool)

Just look at the example config and the code. There are also some hard coded indicator types in the code because who cares.

## Install

There is a `requirements.txt` file.

## Run it

Convience wrapper meant for cron.

Cron:
`*/15 * * * * bin/cofense_collector.sh 2> /opt/cofense_collector/logs/cron.log`

