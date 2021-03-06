#!/usr/bin/env python3

import os
import re
import sys
import uuid
import glob
import json
import logging
import logging.config
import argparse
import coloredlogs
import configparser
import pysip
import traceback

from tabulate import tabulate
from pysip import ConflictError
from datetime import datetime, timedelta

# configure logging #
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')

# we are local
os.environ['no_proxy'] = '.local'

logger = logging.getLogger()
coloredlogs.install(level='INFO', logger=logger)

HOME_PATH = os.path.dirname(os.path.abspath(__file__))

INCOMING_DIR_NAME = 'incoming'
INCOMING_DIR = os.path.join(HOME_PATH, INCOMING_DIR_NAME)
ARCHIVE_DIR_NAME = 'archive'
ARCHIVE_DIR = os.path.join(HOME_PATH, ARCHIVE_DIR_NAME)

PROBLEM_INDICATORS = 'problem_indicators'

REQURIED_DIRS = [PROBLEM_INDICATORS, ARCHIVE_DIR_NAME, 'logs', 'var']

for path in [os.path.join(HOME_PATH, x) for x in REQURIED_DIRS]:
    if not os.path.isdir(path):
        try:
            os.mkdir(path)
        except Exception as e:
            sys.stderr.write("ERROR: cannot create directory {0}: {1}\n".format(
                path, str(e)))
            sys.exit(1)

def write_error_report(message):
    """Record unexpected errors."""
    logging.error(message)
    traceback.print_exc()

    try:
        output_dir = 'error_reporting'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f')), 'w') as fp:
            fp.write(message)
            fp.write('\n\n')
            fp.write(traceback.format_exc())

    except Exception as e:
        traceback.print_exc()

# a list of reports needing deletion
PROCESSED_REPORTS = {}

def report_iterator(target_report_dir=None):
    report_dirs = glob.glob(f"{os.path.join(INCOMING_DIR)}/*")
    report_dirs = sorted(report_dirs, reverse=True)
    if target_report_dir:
        report_dirs = [target_report_dir]
        logging.debug(f"{report_dirs}")
    for report_dir in report_dirs:
        for report_file in glob.glob(f"{os.path.join(INCOMING_DIR, report_dir)}/*"):
            logging.info(f"loading {report_file}")
            report = None
            with open(report_file, 'r') as fp:
                report = json.load(fp)

            PROCESSED_REPORTS[report['id']] = report_file
            yield report

CIDR_REGEX = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$')

def is_ipv4(value):
    """Returns True if the given value is a dotted-quad IP address or CIDR notation."""
    return CIDR_REGEX.match(value) is not None

def get_html_report(report_url):
    from phishme_intelligence import RestApi
    config = configparser.ConfigParser()
    config.read('etc/cofense_config.ini')
    auth = (config['pm_api']['user'], config['pm_api']['pass'])
    cofenseApi = RestApi(config=config, product='pm_api')
    response = cofenseApi.connect_to_api('GET', report_url, auth=auth)
    print(response[1])

    # TODO? for providing to analyst when they click
    return

def create_sip_indicator(sip: pysip.pysip.Client, data: dict):
    """Create a SIP indicator."""
    logging.info(f"Attempting to create SIP indicator with following data: {data}")
    if not data['value']:
        logging.error(f"proposed indicator value is empty.")
        return False

    if '<redacted>' in data['value']:
        old_value = data['value']
        data['value'] = data['value'].replace('<redacted>', '')
        logging.warning(f"appears to be scrubbed indicator value; changing from \"{old_value}\" to \"{data['value']}\"")

    try:
        result = sip.post('/api/indicators', data)
        if 'id' in result:
            logging.info(f"created SIP indicator {result['id']} : {result}")
            return result['id']
    except ConflictError as e:
        logging.info(f"{e} : SIP indicator already exists with value: {data['value']}")
    except Exception as e:
        # this should never happen
        indicator_file = f"{uuid.uuid4()}.json"
        save_path = os.path.join(HOME_PATH, PROBLEM_INDICATORS, indicator_file)
        with open(save_path, 'w') as fp:
            json.dump(data, fp)
        logging.error(f"unidentified problem creating SIP indicator. saved indicator to {save_path}: {e}")
        write_error_report(f"unidentified problem creating SIP indicator. saved indicator to {save_path}: {e}")

    return False

def main():

    parser = argparse.ArgumentParser(description="The tool maps Cofense IOCs from their JSON integration into SIP indicators.")
    parser.add_argument('-d', '--debug', action='store_true', help="Turn on debug logging.")
    parser.add_argument('--logging-config', required=False, default='etc/logging.ini', dest='logging_config',
        help="Path to logging configuration file.  Defaults to etc/logging.ini")
    parser.add_argument('-c', '--config', required=False, default='etc/config.ini', dest='config_path',
        help="Path to configuration file.  Defaults to etc/config.ini")
    parser.add_argument('-p', '--print-indicator-summary', action='store_true', help="Print a summary of all indicators incoming.")
    parser.add_argument('-rd', '--target-report-dir', action='store', default=None, help="only evaluate this report directory")
    parser.add_argument('-grh', '--get-report-html', action='store_true', help="get report html")

    args = parser.parse_args()

    # work out of home dir
    os.chdir(HOME_PATH)

    # initialize logging
    try:
        logging.config.fileConfig(args.logging_config)
    except Exception as e:
        sys.stderr.write("ERROR: unable to load logging config from {0}: {1}".format(
            args.logging_config, str(e)))
        sys.exit(1)

    coloredlogs.install(level='INFO', logger=logging.getLogger())

    if args.debug:
        coloredlogs.install(level='DEBUG', logger=logging.getLogger())

    config = configparser.ConfigParser()
    config.read(args.config_path)

    sip_map = config['sip_mappings']
    # for turning indicator creation on/off by type
    indicator_filter = config['indicator_filter']

    # variables 
    #  - keep a throttle on indicators created per day
    #  - track threats
    indicators_created_today = 0
    max_indicators_per_day = config['collect'].getint('max_indicators_per_day')
    indicator_creation_count_file = os.path.join(HOME_PATH, 'var', f"indicator_count_for_{datetime.now().strftime('%Y-%m-%d')}")
    if not os.path.exists(indicator_creation_count_file):
        logging.info(f"reseting indicator count for a new day..")
        for old_file in glob.glob(f"{os.path.join(HOME_PATH, 'var')}/indicator_count_for_*"):
            logging.info(f"deleting old variable file: {old_file}")
            os.remove(old_file)
        with open(indicator_creation_count_file, 'w') as f:
            f.write(str(0))
    else:
        with open(indicator_creation_count_file, 'r') as f:
            indicators_created_today = f.read()
        indicators_created_today = int(indicators_created_today)

    unique_threat_tracker = {}
    unique_threat_tracker_file =  os.path.join(HOME_PATH, 'var', "unique_threat_tracker.json")
    if os.path.exists(unique_threat_tracker_file):
        with open(unique_threat_tracker_file, 'r') as fp:
            unique_threat_tracker = json.load(fp)

    # connect to sip
    verify_ssl = config['sip'].get('verify_ssl')
    if not os.path.exists(verify_ssl):
        verify_ssl=config['sip'].getboolean('verify_ssl')
    sip = pysip.Client(f"{config['sip'].get('server')}:{config['sip'].get('port')}", config['sip']['api_key'], verify=verify_ssl)

    def _sip_indicator(type: str, 
                       value: str,
                       reference: dict,
                       tags: list,
                       username=config['sip'].get('user'),
                       case_sensitive=False) -> dict:
        # A sip indicator with some defaults defined.
        return { 'type':type,
                 'status': 'New',
                 'confidence': 'low',
                 'impact' : 'unknown',
                 'value' : value,
                 'references' : [ {'source':"Cofense", 'reference': json.dumps(reference)}],
                 'username' :username,
                 'case_sensitive': case_sensitive,
                 'tags': list(set(tags))
                }

    resume_report_id = None
    processed_reports = []
    total_incoming_indicators = []
    for report in report_iterator(target_report_dir=args.target_report_dir):

        if args.get_report_html:
            get_html_report(report['reportURL'])
            return True

        global_tags = []
        for threat in report['malwareFamilySet']:
            if threat['familyName'] == 'Credential Phishing':
                global_tags.append('creds_harvesting')
                continue
            if threat['familyName'] not in unique_threat_tracker:
                logging.info(f"found previously un-seen threat name: {threat['familyName']} - {threat['description']}")
                unique_threat_tracker[threat['familyName']] = threat['description']
    
            if threat['familyName'] not in global_tags:
                global_tags.append(threat['familyName'])

        reference = {'id': report['id'],
                     'reportURL': report['reportURL'], # TODO
                     'executiveSummary': report['executiveSummary']}

        ref_length = len(json.dumps(reference))
        if ref_length > 512:
            # Max length of SIP reference field is 512.
            cut_length = len(reference['executiveSummary']) - (ref_length - 512)
            reference['executiveSummary'] = reference['executiveSummary'][:cut_length]

        # report indicators to post to SIP
        potential_indicators = []

        # process blocksSet
        for block in report['blockSet']:
            _tags = global_tags

            # deduplication happens later
            if block['role'] == "InfURL":
                _tags.append('phishing_url')
            else:
                _tags.append(block['role'])

            itype = sip_map[block['blockType']]
            idata = _sip_indicator(type=itype,
                                   value=block['data'],
                                   reference=reference,
                                   tags=_tags)

            if indicator_filter.getboolean(itype):
                potential_indicators.append(idata)

            # create more indicators
            if block['blockType'] == "URL":

                if block['role'] == "InfURL":
                    # this was a phishing url
                    itype = 'Email - Content - Domain Name'
                    value = block['data_1']['host']
                    idata = _sip_indicator(type=itype,
                                   value=value,
                                   reference=reference,
                                   tags=_tags)
                    idata['tags'].append('domain_in_url')
                    if indicator_filter.getboolean(itype):
                        potential_indicators.append(idata)

                # uri path?
                value = block['data_1']['path']
                if value and len(value) > 9:
                    idata = _sip_indicator(type='URI - Path',
                                           value=value,
                                           reference=reference,
                                           tags=_tags)
                    if indicator_filter.getboolean('URI - Path'):
                        potential_indicators.append(idata)

                # default assume domain name
                itype = 'URI - Domain Name'
                value = block['data_1']['host']
                if is_ipv4(block['data_1']['host']):
                    itype = "Address - ipv4-addr"

                idata = _sip_indicator(type=itype,
                                   value=value,
                                   reference=reference,
                                   tags=_tags)
                if indicator_filter.getboolean(itype):
                    potential_indicators.append(idata)

        # process executableSet
        for malfile in report['executableSet']:
            fileName = malfile.get('fileName')
            if fileName and indicator_filter.getboolean(sip_map['fileName']):
                potential_indicators.append(_sip_indicator(type=sip_map['fileName'], 
                                                       value=fileName,
                                                       reference=reference,
                                                       tags=global_tags))
            sha256Hex = malfile.get('sha256Hex')
            if sha256Hex and indicator_filter.getboolean(sip_map['fileName']):
                potential_indicators.append(_sip_indicator(type=sip_map['sha256Hex'], 
                                                       value=sha256Hex,
                                                       reference=reference,
                                                       tags=global_tags))
            md5Hex = malfile.get('md5Hex')
            if md5Hex and indicator_filter.getboolean(sip_map['fileName']):
                potential_indicators.append(_sip_indicator(type=sip_map['md5Hex'], 
                                                       value=md5Hex,
                                                       reference=reference,
                                                       tags=global_tags))

        # process subjectSet
        for subjectSet in report['subjectSet']:
            subject = subjectSet.get('subject')
            if subject and indicator_filter.getboolean(sip_map['fileName']):
                potential_indicators.append(_sip_indicator(type='Email - Subject', 
                                                       value=subject,
                                                       reference=reference,
                                                       tags=global_tags))

        if args.print_indicator_summary:
            total_incoming_indicators.extend(potential_indicators)
            continue

        for indicator in potential_indicators:
            if indicators_created_today >= max_indicators_per_day:
                resume_report_id = report['id']
                logging.warning(f"maximum indicators created for the day. Will resume report {resume_report_id} tomorrow.")
                break
            if create_sip_indicator(sip, indicator):
                indicators_created_today += 1

        if resume_report_id is not None:
            break

    if args.print_indicator_summary:
        summary_data = []
        for i in total_incoming_indicators:
            summary_data.append({'Report ID': json.loads(i['references'][0]['reference'])['id'],
                                 'type': i['type'],
                                 'value': i['value']})
            #print(f" + type:{i['type']}\t\t\tvalue:{i['value']}")
        print(tabulate(summary_data, headers="keys"))#, tablefmt="github"))
        print(f"\nTotal Incoming Indicators: {len(total_incoming_indicators)}")
        return

    # update records
    try:
        with open(indicator_creation_count_file, 'w') as fp:
            fp.write(str(indicators_created_today))
    except Exception as e:
        logging.error(f"Problem writing indicator count file: {e}")

    try:
        with open(unique_threat_tracker_file, 'w') as fp:
            json.dump(unique_threat_tracker, fp)
    except Exception as e:
        logging.error(f"Problem writing unique threat tracker: {e}")

    # archive processed reports
    for report_id, report_path in PROCESSED_REPORTS.items():
        if resume_report_id == report_id:
            continue
        archive_dir = os.path.dirname(report_path).replace(INCOMING_DIR_NAME, ARCHIVE_DIR_NAME)
        if not os.path.exists(archive_dir):
            os.mkdir(archive_dir)
        archive_path = os.path.join(archive_dir, f"{report_id}.json")
        try:
            os.rename(report_path, archive_path)
        except Exception as e:
            logging.error(f"couldn't archive report: {e}")
        logging.info(f"archived {report_path} to {archive_path}")

    # delete empty dirs
    for report_dir in glob.glob(f"{os.path.join(INCOMING_DIR)}/*"):
        if os.path.isdir(report_dir):
            files = os.listdir(report_dir)
            if len(files) == 0:
                os.rmdir(report_dir)
                logging.info(f"deleted empty report dir: {report_dir}")

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        write_error_report("uncaught exception: {0}".format(str(e)))
