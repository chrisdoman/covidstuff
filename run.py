

'''
Takes input text, creates a pulse and adds it to a group

This uses a simple logic
- Takes free text (eg; from slack)
-- Add all the iocs to a new pulse and add it to the group 'Covid Unvetted'
-- Use the same username/api_key each time
-- Name the pulse the unix timestamp

Note this doesn't check the indicators against a whitelist

A more complicated logic would include the username in the pulse title:
- Takes free text
- Extract IOCs from it
- Check if the pulse 'IOCS - $username - $date' exists
--  If it doesn't exist, then create  the pulse and add to the group
- Adds the IOCs to the pulse

'''

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import time
# pip install iocextract
import iocextract


def create_group_pulse(input_text):
    # Create the pulse title
    unix_time = str( int(time.time()) )
    pulse_title = 'SlackIOCs - ' + unix_time

    API_KEY = ''
    otx = OTXv2(API_KEY)

    group_id = 840

    # Create a list of indicators
    indicators = []

    for url in iocextract.extract_urls(input_text):
        indicators.append({'indicator': url, 'type': 'URL'})

    for ip in iocextract.extract_ips(input_text):
        indicators.append({'indicator': ip, 'type': 'IPv4'})

    for sha256 in iocextract.extract_sha256_hashes(input_text):
        indicators.append({ 'indicator': sha256, 'type': 'FileHash-SHA256' })

    for sha1 in iocextract.extract_sha1_hashes(input_text):
        indicators.append({'indicator': sha1, 'type': 'FileHash-SHA1'})

    for md5 in iocextract.extract_md5_hashes(input_text):
        indicators.append({'indicator': md5, 'type': 'FileHash-MD5'})

    for email in iocextract.extract_emails(input_text):
        indicators.append({ 'indicator': email, 'type': 'EMAIL' })

    print ('Adding ' + str(indicators))

    response = otx.create_pulse(name=pulse_title ,public=True ,indicators=indicators ,tags=['covid19'] , references=[], group_ids=[group_id], tlp='White')

    print ( 'Response: ' + str(response) )

# Example input text from slack or wherever
input_text = '	https://bitbucket.org/example123321/download/downloads/foldingathomeapp.exe	 shannon@litegait.com 66.206.18.186 5df956f08d6ad0559efcdb7b7a59b2f3b95dee9e2aa6b76602c46e2aba855eff '

create_group_pulse( input_text )