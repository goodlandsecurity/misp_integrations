import time
import json
from trustar import TruStar, datetime_to_millis
from datetime import datetime, timedelta
from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert


# initialize TruStar and ExpandedPyMISP
ts = TruStar()
misp = ExpandedPyMISP(url=misp_url, key=misp_key, ssl=misp_verifycert)

# set time for MISP attribute timestamp (doesn't preserve the original trustar report IOC timestamps)
time = time.time()

# set to_time to current time, set from_time depending how often you want to run this script
now = datetime.now()
to_time = datetime.now()
from_time = to_time - timedelta(days=1)

# convert to millis since epoch for TruStar
to_time = datetime_to_millis(to_time)
from_time = datetime_to_millis(from_time)

# set RH-ISAC enclave id to variable
rhisac = "7a33144f-aef3-442b-87d4-dbf70d8afdb0"

# set API call to variable to get reports from TruStar from RH-ISAC enclave within specified time frame
reports = ts.get_reports(from_time=from_time, to_time=to_time, is_enclave=True, enclave_ids=rhisac)


for report in reports:
    info_dict = []
    attr_dict = []
    tag_dict = []

    # grab the report body from TruStar and add as an attribute to the MISP event
    report_body = {
        "timestamp": time,
        "to_ids": False,
        "category": "External analysis",
        "type": "comment",
        "value": report.body
    }

    # get all tags for the report and create in MISP if don't exist
    for tag in ts.get_enclave_tags(report.id):
        tag_type = {
            "exportable": True,
            "name": tag.name
        }
        tag_dict.append(tag_type)

    # append the report body attribute to the attribute dictionary for each event
    attr_dict.append(report_body)

    # get indicators for report
    for indicator in ts.get_indicators_for_report(report.id):

        # map trustar indicator type to MISP format
        indicator_type = {
            "MD5": "md5",
            "SHA1": "sha1",
            "SHA256": "sha265",
            "SOFTWARE": "filename",
            "URL": "link",
            "EMAIL_ADDRESS": "email-src",
            "IP": "ip-dst",
            "MALWARE": "malware-type",
            "CIDR_BLOCK": "ip-src"
        }

        # for each indicator create an attribute list
        attribute = {
            "timestamp": time,
            "to_ids": False,
            "category": "Payload delivery",
            "type": indicator_type.get(indicator.type),
            "value": indicator.value
        }

        # for each report create an event list
        event = {
            "Event": {
                "info": report.title,
                "date": now.strftime("%Y-%m-%d"),
                "Orgc": {
                    'uuid': '22aa7e1a-adac-486d-8037-a3bc1bd6505f',
                    'name': 'RH-ISAC'
                },
                "published": False,
                "analysis": "0",
                "Attribute": attr_dict,
                "Tag": tag_dict
            }
        }

        # append attribute list to dictionary
        attr_dict.append(attribute)

    # dump event dictionary to json format
    event_json = json.dumps(event)
    
    # for each report api call to MISP to create event
    misp.add_event(event_json)
