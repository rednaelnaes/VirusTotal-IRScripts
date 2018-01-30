#Virus Total Command Line Tool#
#Utility for on the fly threat intel

import requests
import os
import sys
import json
import argparse
from pprint import pprint as pp

parser = argparse.ArgumentParser(description='Virus Total CLI: Command Line Tool for Submitting to Virus Total')
parser.add_argument('-i', '--ip', help='IP eg; 4.4.4.4', required=False)
parser.add_argument('-u', '--url', help='URL eg; https://www.google.com', required=False)
parser.add_argument('-f', '--file', help='File Hash eg; SHA1, MD5, SHA256', required=False)
args = parser.parse_args()

API = raw_input('Enter Your Virus Total Public API key:')
#There are better ways to handle this^^^

#endpoint defined elsewhere
base_url = "https://www.virustotal.com/vtapi/v2"

#checks response code.  need to expand error handling.
def chk_resp(vtresult):
	if vtresult['response_code'] == 0:
		print "Virus Total has no information regarding this submission"
		sys.exit()

#primary function responsible for sending GET requests
def vtrequest(parameters,endpoint):
	params = parameters
	headers = {"Accept-Encoding": "gzip, deflate","User-Agent": "Python Client"}
	response = requests.get(endpoint, params=params, headers=headers)
	json_response = response.json()
	return json_response

#drill down through json object enumerating pertinent info
def ipinfo(vtresult,info,data):
	for nest in info:
		for item in vtresult[nest]:
			for dat in data:
				if dat in item:
					print item[dat]

#detection ratio for URLs
def urlinfo():
	total_detections = vtresult['positives']
	if total_detections > 1:
		print "Site detected as malicious by " + str(total_detections) + " vendors:"
		for vendor in vtresult['scans']:
			if vtresult['scans'][vendor]['detected'] == True:
				print vendor
#checks to see if AV thinks hash is evil
#can be modified to check for other vendors
def hashinfo():
	if vtresult['positives'] > 1:
		test = vtresult['positives']
		print "This many vendors detect this as malicious:" + str(test)
		if vtresult['scans']['TrendMicro']['detected'] == True:
			print "But have no fear!  Trend Micro detects this threat."
		if vtresult['scans']['TrendMicro']['detected'] == False:
			print "Trend Micro does not detect this threat!"

#parse through arguments setting variables
if args.ip:
	parameters = {'apikey': API, 'ip': args.ip}
	endpoint = base_url + '/ip-address/report'
	info = ['resolutions','detected_urls','detected_downloaded_samples']
	data = ['hostname','url','sha256']
	print "Listing associated domains, urls, and file hashes:"

elif args.url:
	parameters = {'apikey': API, 'resource': args.url}
	endpoint = base_url+'/url/report'
	info = ['positives','scans','total']

elif args.file:
	parameters = {'apikey': API, 'resource': args.file}
	endpoint = base_url+'/file/report'

#call functions
#need error handled for parameters not defined
vtresult = vtrequest(parameters,endpoint)
chk_resp(vtresult)

#flow control using arguments
if args.ip: ipinfo(vtresult,info,data)
if args.url: urlinfo()
if args.file: hashinfo()

