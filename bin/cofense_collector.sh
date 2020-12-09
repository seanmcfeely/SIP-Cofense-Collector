#!/usr/bin/env bash
# just for cron use
# cron example: */15 * * * * /opt/cofenseCollector/bin/cofense_collector.sh 2> /opt/cofenseCollector/logs/cron.log

HOME_DIR="/opt/cofenseCollector"

cd $HOME_DIR || { echo "$HOME_DIR does not exist. exiting."; exit 1;}

# proxy?
# phishme_intlligence doesn't properly use proxy
bin/proxy_settings.sh

# activate venv
#source venv/bin/activate

# get any new reports
python3 -m phishme_intelligence -conf etc/cofense_config.ini

# process any reports
python3 cofense_collector.py
