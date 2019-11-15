from trustar import TruStar, datetime_to_millis
from datetime import datetime, timedelta
from keys import misp_url, misp_key, misp_verifycert
from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation


# TODO: Work on reducing false positive attributes
#       (e.g. email addresses from RH-ISAC members being pulled from TruStar reports)
#   Signature whitelisting can be done on MISP with regex entries (in the standard php
#   regex /{regex}/{modifier} format) entered on http://MISP.local/admin/whitelists/index
#   to restrict matching attributes from being included in the IDS flag sensitive exports

# initialize TruStar()
tru = TruStar()

# initialize ExpandedPyMISP()
misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

now = datetime.now()

# date range for pulling reports can be hours= or days=
to_time = datetime.now()
from_time = to_time - timedelta(hours=6)

# convert to millis since epoch
to_time = datetime_to_millis(to_time)
from_time = datetime_to_millis(from_time)

rhisac = "7a33144f-aef3-442b-87d4-dbf70d8afdb0" # TruStar RH-ISAC enclave uuid
reports = tru.get_reports(from_time=from_time,
                         to_time=to_time,
                         is_enclave=True,
                         enclave_ids=rhisac)

# loop through each trustar report and create MISP event
for report in reports:
    # initialize and set MISPOrganisation()
    orgc = MISPOrganisation()
    orgc.name = 'RH-ISAC'
    orgc.id = '#{ORGC_ID}'  # organisation id
    orgc.uuid = '#{ORGC_UUID}'  # organisation uuid
    # initialize and set MISPEvent()
    event = MISPEvent()
    event.Orgc = orgc
    event.info = report.title
    event.distribution = 0  # Optional, defaults to MISP.default_event_distribution in MISP config
    event.threat_level_id = 2  # Optional, defaults to MISP.default_event_threat_level in MISP config
    event.analysis = 0  # Optional, defaults to 0 (initial analysis)

    # get tags for report
    for tag in tru.get_enclave_tags(report.id):
        event.add_tag(tag.name)

    # get indicators for report
    for indicator in tru.get_indicators_for_report(report.id):

        # map trustar indicator type to MISP format
        indicator_type = {
            "MD5": "md5",
            "SHA1": "sha1",
            "SHA256": "sha256",
            "SOFTWARE": "filename",
            "URL": "link",
            "EMAIL_ADDRESS": "email-src",
            "IP": "ip-dst",
            "MALWARE": "malware-type",
            "CIDR_BLOCK": "ip-src",
            "CVE": "vulnerability",
            "THREAT_ACTOR": "threat-actor"
        }
        event.add_attribute(indicator_type.get(indicator.type), indicator.value)

    # post each event to MISP via api
    misp.add_event(event.to_json())