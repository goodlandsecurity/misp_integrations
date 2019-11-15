import requests
import json
from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation
from keys import misp_url, misp_key, misp_verifycert


# initialize PyMISP
misp = ExpandedPyMISP(url=misp_url, key=misp_key, ssl=misp_verifycert)

url = "https://tap-api-v2.proofpoint.com/v2/siem/all"

alertType = ("messagesBlocked", "messagesDelivered")

# TODO:
#   clicks:
#       add functionality to collect clicksPermitted and clicksBlocked TAP alerts in same script
#   messages:
#       if messagesBlocked; quarantineFolder & quarantineRule
#   all alerts:
#       if headerReplyTo != null OR ''; event.add_attribute('comment', messages["headerReplyTo"])
#       if ccAddresses != null OR ''; event.add_attribute('comment', messages["ccAddresses"])
#       if replyTo != null OR ''; event.add_attribute('comment', messages["replyTo"])
#       if toAddresses != null OR ''; event.add_attribute('comment', messages["toAddresses"])
#       if xmailer != null OR ''; event.add_attribute('comment', messages["xmailer"])


# max query is 1h, and we want Proofpoint TAP api to return json
queryString = {
    "sinceSeconds": "3600",
    "format": "json"
}

# auth to api needs to be set as a header, not as part of the query string
headers = {
    'Authorization': "Basic #{API_KEY}"  # add your Proofpoint TAP api key here
}

response = requests.request("GET", url, headers=headers, params=queryString)

jsonData = json.loads(response.text)

for alert in alertType:
    for messages in jsonData[alert]:
        orgc = MISPOrganisation()
        orgc.name = 'Proofpoint'
        orgc.id = '#{ORGC_ID}'  # organisation id
        orgc.uuid = '#{ORGC_UUID}'  # organisation uuid
        # initialize and set MISPEvent()
        event = MISPEvent()
        event.Orgc = orgc
        event.info = alert
        event.distribution = 0  # Optional, defaults to MISP.default_event_distribution in MISP config
        event.threat_level_id = 0  # Optional, defaults to MISP.default_event_threat_level in MISP config
        event.analysis = 0  # Optional, defaults to 0 (initial analysis)

        recipient = event.add_attribute('email-dst', messages["recipient"][0])
        recipient.comment = 'recipient address'

        sender = event.add_attribute('email-src', messages["sender"])
        sender.comment = 'sender address'

        fromAddress = event.add_attribute('email-src-display-name', messages["fromAddress"])
        # for reasons unbeknownst to me, uncommenting the following line breaks this attribute from posting
        # fromAddress.comment = 'from address'

        headerFrom = event.add_attribute('email-header', messages["headerFrom"])
        headerFrom.comment = 'email header from'

        senderIP = event.add_attribute('ip-src', messages["senderIP"])
        senderIP.comment = 'sender IP'

        subject = event.add_attribute('email-subject', messages["subject"])
        subject.comment = 'email subject'

        messageSize = event.add_attribute('size-in-bytes', messages["messageSize"])
        messageSize.comment = 'size of email in bytes'

        malwareScore = event.add_attribute('comment', messages["malwareScore"])
        malwareScore.comment = 'malware score'

        phishScore = event.add_attribute('comment', messages["phishScore"])
        phishScore.comment = 'phish score'

        spamScore = event.add_attribute('comment', messages["spamScore"])
        spamScore.comment = 'spam score'

        imposterScore = event.add_attribute('comment', messages["impostorScore"])
        imposterScore.comment = 'impostor score'

        completelyRewritten = event.add_attribute('comment', messages["completelyRewritten"])
        completelyRewritten.comment = 'proofpoint url defense'

        # grab the threat info for each message in TAP
        for threatInfo in messages["threatsInfoMap"]:
            threat_type = {
                "url": "url",
                "attachment": "email-attachment",
                "message": "email-body"
            }

            threat = event.add_attribute(threat_type.get(threatInfo["threatType"]), threatInfo["threat"])
            threat.comment = 'threat'

            threatUrl = event.add_attribute('link', threatInfo["threatUrl"])
            threatUrl.comment = 'link to threat in TAP'

            threatStatus = event.add_attribute('comment', threatInfo["threatStatus"])
            threatStatus.comment = "proofpoint's threat status"


            event.add_tag(threatInfo["classification"])

        # grab which policy route the message took
        for policy in messages["policyRoutes"]:
            policyRoute = event.add_attribute('comment', policy)
            policyRoute.comment = 'email policy route'

        # was the threat in the body of the email or is it an attachment?
        for parts in messages["messageParts"]:
            disposition = event.add_attribute('comment', parts["disposition"])
            disposition.comment = 'email body or attachment'

            # sha256 hash of threat
            sha256 = event.add_attribute('sha256', parts["sha256"])
            sha256.comment = 'sha256 hash'

            # md5 hash of threat
            md5 = event.add_attribute('md5', parts["md5"])
            md5.comment = 'md5 hash'

            # filename of threat
            filename = event.add_attribute('filename', parts["filename"])
            filename.comment = 'filename'

        misp.add_event(event.to_json())
        