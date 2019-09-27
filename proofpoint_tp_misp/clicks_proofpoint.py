import json
from datetime import datetime
import time
from pymisp import ExpandedPyMISP
import requests

misp = ExpandedPyMISP(url='Your MISP', key='API KEY', ssl='True')

#Proofpoint TAP API CALL
url = "https://tap-api-v2.proofpoint.com/v2/siem/all"

querystring = {"format": "json", "sinceSeconds": "3600"}

headers = {
    'Authorization': "Basic 'API KEY'",
    'Accept': "*/*",
    'Cache-Control': "no-cache",
    'Host': "tap-api-v2.proofpoint.com",
    'Accept-Encoding': "gzip, deflate",
    'Connection': "keep-alive",
    'cache-control': "no-cache"
}

#Defining Global Variables
response = requests.request("GET", url, headers=headers, params=querystring)
alert_type = ("clicksPermitted", "clicksBlocked")
var = json.loads(response.text)
ts = time.time()
now = datetime.now()

#For Loop Structure
for type_alert in alert_type:

    for event in var[type_alert]:

        for recipient in event["recipient"]:
                    tag_type = {
                "malware": "Malware",
                "phish": "Phish",
                "spam": "Spam"
            }
                    tag_colour = {
                "malware": "#0000FF",
                "phish": "#7FE5F0",
                "spam": "#FF0000"
            }

                    tag = {
                "colour": tag_colour.get(threat_map["classification"]),
                "exportable": False,
                "name": tag_type.get(threat_map["classification"])
            }
                    tags = []
                    tags.append(tag)


                    sender_ip = {
                "comment": "source",
                "category": "External analysis",
                "timestamp": ts,
                "to_ids": False,
                "value": event["senderIP"],
                "disable_correlation": False,
                "object_relation": "",
                "type": "ip-src"
            }
                    sender_address = {
                "comment": "source",
                "category": "Payload delivery",
                "timestamp": ts,
                "to_ids": False,
                "value": event["sender"],
                "disable_correlation": False,
                "object_relation": "",
                "type": "email-src-display-name"
            }

                    destination = {
                "comment": "destination",
                "category": "Payload delivery",
                "timestamp": ts,
                "to_ids": False,
                "value": recipient,
                "disable_correlation": False,
                "object_relation": "",
                "type": "email-dst-display-name"
            }
                    click_url = {
                "comment": "click url",
                "category": "Payload delivery",
                "timestamp": ts,
                "to_ids": False,
                "value": event["url"],
                "disable_correlation": False,
                "object_relation": "",
                "type": "email-dst-display-name"
            }
                    click_ip = {
                "comment": "click ip",
                "category": "Payload delivery",
                "timestamp": ts,
                "to_ids": False,
                "value": event["clickIP"],
                "disable_correlation": False,
                "object_relation": "",
                "type": "email-dst-display-name"
            }

                    urls = []
                    urls.append(sender_ip)
                    urls.append(destination)
                    urls.append(sender_address)
                    urls.append(click_url)
                    urls.append(click_ip)
                    EventDict = {
                "Event": {
                "info": type_alert,
                "publish_timestamp": ts,
                "timestamp": ts,
                "analysis": "2",
                "Tag": tags,
                "Attribute": urls,
                "extends_uuid": "",
                "published": False,
                "date": now.strftime("%Y-%m-%d"),
                "Orgc": {
                    "uuid":Your uid",
                    "name": "Proofpoint"
                        },
                }

            }
        misp.add_event(EventDict)
