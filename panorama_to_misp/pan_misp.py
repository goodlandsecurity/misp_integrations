import requests
import xmltodict
import json
from datetime import datetime
from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert

now = datetime.now()
misp = ExpandedPyMISP(url=misp_url, key=misp_key, ssl=misp_verifycert)

url = "https://PANORAMA/api/"

querystring = {
    "type":"report",
    "async":"yes",
    "reporttype":"predefined",
    "reportname":"top-attacks",
    "key":"API KEY"
}

headers = {
    'Accept': "*/*",
    'Cache-Control': "no-cache",
    }

response = requests.request("GET", url, headers=headers, params=querystring)

resp_text = response.text

json_data = json.loads(json.dumps(xmltodict.parse(resp_text)))


event_list = []
attribute_list = []


event = {
            "Event": {
                "info": json_data['report']['result']['@name'] + " | " + json_data['report']['result']['@range'],
                "date": now.strftime("%Y-%m-%d"),
                "Orgc": {
                    'uuid': 'MISP ORG UUID',
                    'name': 'Palo Alto'
                },
                "published": False,
                "analysis": "0",
                "Attribute": attribute_list,
                "Tag": {
                    "exportable": True,
                    "name": "firewall threats"
                }
            }
        }


for threatid in json_data['report']['result']['entry']:
    attribute = {
        "to_ids": False,
        "category": "External analysis",
        "type": "comment",
        "value": threatid['threatid'],
        "comment": threatid['count']
    }
    attribute_list.append(attribute)

event_list.append(event)
event_json = json.dumps(event_list)
misp.add_event(event_json)

