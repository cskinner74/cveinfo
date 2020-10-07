# CVEInfo

A tool to get basic info about a CVE from the command line

## Setup
Python 3.7+ required.
run `pip3 install -r requirements.txt` to install necessary python packages.

## Usage:
`cveinfo.py [-e] <CVE>`

Example:
`cveinfo.py 2019-10241`

The `-e` option will attempt to search for data on a linked CWE if it exists.
