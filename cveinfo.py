#!/usr/bin/python3

# CVEINFO
# A script to get quick info on CVEs from the command line
# Written by: Cody Skinner
# @TheCodySkinner

import argparse
import json
import requests

#Get command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("CVE", help="CVE code (ex. 2020-1234)")
parser.add_argument("-e", "--cwe", help="Attempt to pull data on related CWE", action="store_true")
args = parser.parse_args()

#Set vars
cve = args.CVE
url = 'https://cve.circl.lu/api/cve/CVE-' + cve
response = requests.get(url)
data = response.json()

#Check for result
if data is None:
    print("No results found for CVE. Exiting.")
    exit(1)

#Get data
cvid = data['id']
modified = data['Modified']
published = data['Published']
cvss = data['cvss']
rel_cwe = data['cwe']
impact = data['impact']
references = data['references']
summary = data['summary']
vulnerable = data['vulnerable_product']

print('CVE: ' + cvid)
print('CVSS Score: ' + str(cvss))
print('Published: ' + published)
print('Modified: ' + modified)
print('CWE: ' + rel_cwe)
for (k, v) in impact.items():
    print('Impact to ' + k + ': ' + v)
for (reference) in references:
    print('Reference: ' + reference)
print('\n\nSummary:\n' + summary)
print('\n\nVulnerable Products:')
for product in vulnerable:
    print(product)

#Get CWE
if args.cwe:
    #rel_cwe.removeprefix('CWE-') Python 3.9+, wait to implement until Python 3.9 is more widely adopted
    rel_cwe = rel_cwe[4:]
    cweurl = 'https://cve.circl.lu/api/capec/'+rel_cwe
    cweresp = requests.get(cweurl)
    cwedata = cweresp.json()
    print('\n\nCWE INFO:')
    if cwedata is not None:
        cwe_id = cwedata['id']
        cwe_name = cwedata['name']
        cwe_prereq = cwedata['prerequisites']
        cwe_relweak = cwedata['related_weakness']
        cwe_summary = cwedata['summary']
        print('CWE: ' + cwe_id)
        print('Name: ' + cwe_name)
        print('Prerequisites: ' + cwe_prereq)
        print('Related Weakness: ' + cwe_relweak)
        print('\n\nSummary:\n' + cwe_summary)
    else:
        print('Data could not be found for this CWE')

