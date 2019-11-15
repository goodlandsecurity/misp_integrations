import requests
import xmltodict
import json
from datetime import datetime
from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation
from keys import misp_url, misp_key, misp_verifycert

now = datetime.now()
# initialize ExpandedPyMISP()
misp = ExpandedPyMISP(url=misp_url, key=misp_key, ssl=misp_verifycert)

url = 'https://#{PANORAMA}/api/'

querystring = {
    "type":"report",
    "async":"yes",
    "reporttype":"predefined",
    "reportname":"top-attacks",
    "key":"#{API_KEY}"  # put your Panorama api key here
}

# try with "..., verify=False)" if you get an SSL error
response = requests.request("GET", url, params=querystring)

resp_text = response.text

json_data = json.loads(json.dumps(xmltodict.parse(resp_text)))

# initialize and set MISPOrganisation
orgc = MISPOrganisation()
orgc.name = 'Palo Alto'
orgc.id = '#{ORGC_ID}'  # organisation id
orgc.uuid = '#{ORGC_UUID}'  # organisation uuid
# initialize and set MISPEvent()
event = MISPEvent()
event.Orgc = orgc
event.info = json_data['report']['result']['@name'] + " | " + json_data['report']['result']['@range']
event.distribution = 0  # Optional, defaults to MISP.default_event_distribution in MISP config
event.threat_level_id = 0  # Optional, defaults to MISP.default_event_threat_level in MISP config
event.analysis = 0  # Optional, defaults to 0 (initial analysis)
event.add_tag('firewall threats')

for threatid in json_data['report']['result']['entry']:
    attribute = event.add_attribute('comment', threatid['threatid'])
    attribute.comment = threatid['count']

misp.add_event(event.to_json())
