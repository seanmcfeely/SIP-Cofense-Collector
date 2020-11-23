#!/usr/bin/env bash
# just for cron use
# cron example: */15 * * * * /opt/cofenseCollector/bin/cofense_collector.sh 2> /opt/cofenseCollector/logs/cron.log

HOME="/opt/cofenseCollector"

cd $HOME || { echo "$HOME does not exist. exiting."; exit 1;}

# get any new reports
venv/bin/python3 -m phishme_intelligence -conf etc/cofense_config.ini

# process any reports
python3 cofense_collector.py
