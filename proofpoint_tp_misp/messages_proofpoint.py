import json
from datetime import datetime
import time
from pymisp import ExpandedPyMISP
import requests

#Defining MISP INSTANCE
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
alert_type = ("messagesBlocked", "messagesDelivered")
var = json.loads(response.text)
ts = time.time()
now = datetime.now()

#For Loop Structure
for type_alert in alert_type:

    for event in var[type_alert]:
        urls = []
        tags = []
        colour = []
        for recipient in event["recipient"]:

            for from_address in event["fromAddress"]:

                for threat_map in event["threatsInfoMap"]:

                            threat_type = {
                        "url": "url",
                        "attachment": "filename",
                        "message": "email-body"
                    }

                            tag_type = {
                        "malware": "Malware",
                        "phish": "Phish",
                        "spam": "Spam",
                        "impostor": "Impostor"
                    }
                            tag_colour = {
                        "malware": "#0000FF",
                        "phish": "#7FE5F0",
                        "spam": "#FF0000",
                        "impostor": "#e0e22a"
                    }

                            tag = {
                        "colour": tag_colour.get(threat_map["classification"]),
                        "exportable": True,
                        "name": tag_type.get(threat_map["classification"])
                    }
                            tags.append(tag)


                            threat_info = {
                        "comment": threat_map["threatType"],
                        "category": "Payload delivery",
                        "timestamp": ts,
                        "to_ids": False,
                        "value": threat_map["threat"],
                        "disable_correlation": False,
                        "object_relation": "",
                        "type": threat_type.get(threat_map["threatType"])
                    }
                            sender_ip = {
                        "comment": "Sender IP",
                        "category": "Payload delivery",
                        "timestamp": ts,
                        "to_ids": False,
                        "value": event["senderIP"],
                        "disable_correlation": False,
                        "object_relation": "",
                        "type": "ip-src"
                    }
                            sender_address = {
                        "comment": "Sender Address",
                        "category": "Payload delivery",
                        "timestamp": ts,
                        "to_ids": False,
                        "value": from_address,
                        "disable_correlation": False,
                        "object_relation": "",
                        "type": "email-src-display-name"
                            }

                            destination = {
                        "comment": "Destination Address",
                        "category": "Payload delivery",
                        "timestamp": ts,
                        "to_ids": False,
                        "value": recipient,
                        "disable_correlation": False,
                        "object_relation": "",
                        "type": "email-dst-display-name"
                    }

                            urls.append(threat_info)
                            urls.append(sender_ip)
                            urls.append(destination)
                            urls.append(sender_address)
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
                            "uuid": "Your UUID",
                            "name": "Proofpoint"
                                },
                        }
                    }
    misp.add_event(EventDict)
