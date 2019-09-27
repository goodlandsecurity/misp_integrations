import requests
import json
import time
from datetime import datetime
from pymisp import ExpandedPyMISP

misp = ExpandedPyMISP(url='Your MISP', key='API KEY', ssl='True')

url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

headers = {
    'Accept': "*/*",
    'Cache-Control': "no-cache",
    'Host': "urlhaus-api.abuse.ch",
    'Accept-Encoding': "gzip, deflate",
    'Connection': "keep-alive",
    'cache-control': "no-cache"
    }

response = requests.request("GET", url, headers=headers)

var = json.loads(response.text)
now = datetime.now()
ts = time.time()
attr = []

for feed in var["urls"]:
    attribute = {
        "comment": "Malicious URL",
        "category": "External analysis",
        "timestamp": ts,
        "to_ids": False,
        "value": feed["url"],
        "disable_correlation": False,
        "object_relation": "",
        "type": "url"
    }
    attributeHost = {
        "comment": "Malicious Host",
        "category": "External analysis",
        "timestamp": ts,
        "to_ids": False,
        "value": feed["host"],
        "disable_correlation": False,
        "object_relation": "",
        "type": "url"
    }
    attr.append(attribute)
    attr.append(attributeHost)

    EventDict = {
        "Event": {
            "info": "URL Haus Known Bad",
            "publish timestamp": ts,
            "analysis": 2,
            "Tag": {
                "colour": "ff0000",
                "exportable": True,
                "name": "Malicious URLs"
            },
            "Attribute": attr,
            "threat_level_id": "1",
            "extends_uuid": "",
            "published": False,
            "date": now.strftime("%Y-%m-%d"),
            "Orgc": {
                "uuid": "Your UUID",
                "name": "URL Haus"
            },

        }
    }
misp.add_event(EventDict)
