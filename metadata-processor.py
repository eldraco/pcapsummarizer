#!/usr/bin/env python3
# Script to manage the creation/update/comsuption of the metadata files for the Stratosphere Datasets
# Author: Garcia Sebastian, eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz
import argparse
import sys
import os
import time
from datetime import datetime
import json
import subprocess
import glob
import requests
from datetime import timedelta

version = '0.1'


####################
# Main
####################
if __name__ == '__main__':
    print('Stratosphere Dataset Metadata Manager. Version {}'.format(version))
    print('https://stratosphereips.org\n')

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the program.', action='store', required=False, type=int)
    parser.add_argument('-c', '--createfrom', help='Create a metadata json from this folder', required=False)
    parser.add_argument('-o', '--output', help='Store the metadata json in this file. Defaults to README.json', type=str, default='README.json', required=False)
    parser.add_argument('-p', '--pcapfile', help='Pcap file to read. Zeek is run on it and slips interfaces with Zeek.', required=False)
    parser.add_argument('-r', '--read', help='Read a README.json file and show the data.', required=False)
    args = parser.parse_args()

    if not args.createfrom and not args.read:
        print('You need a README.md file to start the conversion, or a README.json to read.')
        sys.exit()

    if args.createfrom:
        # Create a new JSON metadata file from a README.md

        metadata = {}
        metadata['Name'] = 'Stratosphere Dataset Capture'
        metadata['Description'] = 'Capture Dataset created at the Stratosphere Laboratory, CVUT University.'
        metadata['Duration'] = ''
        metadata['Author'] = 'Stratosphere Laboratory'
        metadata['Contact'] = 'stratosphere@aic.fel.cvut.cz'
        metadata['Disclaimer'] = 'These files were generated in the Stratosphere Laboratory, AIC group, as part of the Aposemat Project with the support of Avast Software to collect IoT captures at the Czech Technical University, Prague, Czech Republic.'
        metadata['License'] = 'https://creativecommons.org/licenses/by/3.0/'
        metadata['Password'] = "The password of the compressed file is 'infected'"

        # From README.md file
        readmefile = os.path.join(args.createfrom, 'README.md')
        out = subprocess.Popen(["grep", "-i", "Description:", readmefile], stdout=subprocess.PIPE)
        description = ' '.join(out.communicate()[0].decode("utf-8").split()[2:])
        if description:
            metadata['Description'] = description

        ## Get dataset name if possible
        out = subprocess.Popen(["grep", "-i", "Generic Dataset name", readmefile], stdout=subprocess.PIPE)
        name = ' '.join(out.communicate()[0].decode("utf-8").split()[4:])
        if name:
            metadata['Name'] = name
        else:
            # There was no name in the README.md, use the folder name
            name = args.createfrom.rstrip('\\').split('/')[0]
            if name:
                metadata['Name'] = name

        ## If it was malware, get malware name
        out = subprocess.Popen(["grep", "-i", "Probable Malware Name", readmefile], stdout=subprocess.PIPE)
        malwarename = ' '.join(out.communicate()[0].decode("utf-8").split()[4:])
        if malwarename:
            metadata['Malware Name'] = malwarename
        else:
            # Try a variation
            out = subprocess.Popen(["grep", "-i", "Probable Name", readmefile], stdout=subprocess.PIPE)
            malwarename = ' '.join(out.communicate()[0].decode("utf-8").split()[3:])
            if malwarename:
                metadata['Malware Name'] = malwarename


        ## If it was malware, get the sha256
        out = subprocess.Popen(["grep", "-i", "SHA256", readmefile], stdout=subprocess.PIPE)
        sha256 = ' '.join(out.communicate()[0].decode("utf-8").split()[2:])
        if sha256:
            metadata['SHA256'] = sha256

        ## Get the IP
        out = subprocess.Popen(["grep", "-i", "Infected device:", readmefile], stdout=subprocess.PIPE)
        ip = ' '.join(out.communicate()[0].decode("utf-8").split()[3:])
        if ip:
            metadata['PrivateIP'] = ip
       
        # From capinfos
        ## First packet time
        capinfofile = glob.glob(args.createfrom + "/*.capinfos")[0]
        out = subprocess.Popen(["grep", "-i", "First packet time:", capinfofile], stdout=subprocess.PIPE)
        timefirstpacket = ' '.join(out.communicate()[0].decode("utf-8").split()[3:])
        if timefirstpacket and '1970' not in timefirstpacket:
            metadata['Start'] = timefirstpacket
        else:
            # We have the case of the pcap captured in the Virtualbox so, the pcap time is wrong. 
            # Try to fix later from README.md
            metadata['Start'] = ''

        ## Last packet time
        out = subprocess.Popen(["grep", "-i", "Last packet time:", capinfofile], stdout=subprocess.PIPE)
        timelastpacket = ' '.join(out.communicate()[0].decode("utf-8").split()[3:])
        if timelastpacket and '1970' not in timefirstpacket:
            metadata['End'] = timelastpacket
        else:
            # We have the case of the pcap captured in the Virtualbox so, the pcap time is wrong
            # Try to fix later from README.md
            metadata['End'] = ''

        ## Duration
        out = subprocess.Popen(["grep", "-i", "Capture duration:", capinfofile], stdout=subprocess.PIPE)
        timelastpacket = ' '.join(out.communicate()[0].decode("utf-8").split()[2:])
        if timelastpacket:
            metadata['Duration'] = timelastpacket

        # Timeline of comments
        with open(readmefile, 'r') as f:
            line = f.readline()
            timeline = {}
            timeline_text = ''
            while line:
                if 'Timeline' in line:
                    # We found the first marker
                    line = f.readline()
                    while line and 'Disclaimer' not in line:
                        # Search of the dates and text
                        if '#' in line:
                            # is a datetime
                            date = line.strip('#').strip('\n').strip()
                            # If we dont have a start time, use it
                            if not metadata['Start']:
                                metadata['Start'] = date
                            # Store the date
                            timeline[date] = ''
                            line = f.readline()
                            while '#' not in line:
                                timeline[date] = timeline[date] + line.strip('\n').strip()
                                line = f.readline()
                        line = f.readline()
                    # Get out of the file after the disclaimer
                    break
                line = f.readline()
        metadata['timeline'] = timeline

        # Fix the ending time if needed
        if not metadata['End']:
            startdateobj =  datetime.strptime(metadata['Start'], '%a %b %d %H:%M:%S %Z %Y')
            durationobj = timedelta(seconds=int(metadata['Duration'].split('.')[0]))
            enddateobj = startdateobj + durationobj
            metadata['End'] = enddateobj.strftime("%a %b %d %H:%M:%S %Z %Y")

        # Add URL
        URL = 'https://mcfp.felk.cvut.cz/publicDatasets/' + name
        try:
            response_code = requests.get(URL).status_code
            if response_code == 200:
                # Is ok
                metadata['URL'] = URL
                badurl = False
            else:
                badurl = True
        except requests.ConnectionError as exception:
            # Not even an open port
            badurl = True

        if badurl:
            # Lets check the IoTScenarios
            URL = 'https://mcfp.felk.cvut.cz/publicDatasets/IoTDatasets/' + name
            try:
                response_code = requests.get(URL).status_code
                if response_code == 200:
                    metadata['URL'] = URL
                else:
                    print(f'The URL {URL} for {name} is not 200 OK. Check it manually.')
                    URL = input('Enter URL: ')
            except requests.ConnectionError as exception:
                # Not even an open port
                print(f'The URL {URL} for {name} is not 200 OK. Check it manually.')
                URL = input('Enter URL: ')

        metadata['URL'] = URL


        # From each File
        metadata['Files'] = {}
        entries = os.listdir(args.createfrom)
        for entry in entries:
            if 'capinfo' in entry:
                metadata['Files']['capinfos'] = {'Description': 'Capinfos tool', 'File': metadata['URL'] + '/' + entry}
            elif 'dnstop' in entry:
                metadata['Files']['dnstop'] = {'Description': 'Dnstop  tool', 'File': metadata['URL'] + '/' + entry}
            elif 'passivedns' in entry:
                metadata['Files']['passivedns'] = {'Description': 'Passivedns  tool', 'File': metadata['URL'] + '/' + entry}
            elif 'pcap' in entry:
                metadata['Files']['pcap'] = {'Description': 'Pcap file', 'File': metadata['URL'] + '/' + entry}
            elif 'bro' in entry:
                metadata['Files']['Zeek'] = {'Description': 'Zeek folder with logs', 'File': metadata['URL'] + '/' + entry}
                # LastUpdate: 2021/02/20 09:23:23.232323
            elif 'suricata' in entry:
                out = subprocess.Popen(["grep", "-i", "Suricata run", readmefile], stdout=subprocess.PIPE)
                suricataupdate = ' '.join(out.communicate()[0].decode("utf-8").split()[7:])
                if not suricataupdate:
                    suricataupdate = 'Unknown'
                metadata['Files']['Suricata'] = {'Description': 'Suricata folder with logs', 'LastUpdate': suricataupdate ,'File': metadata['URL'] + '/' + entry}
            elif '.zip' in entry:
                # Zip file
                metadata['Files']['Zip'] = {'Description': 'Zip file with the malware. Password infected', 'File': metadata['URL'] + '/' + entry}
            elif '.json' in entry or 'README' in entry:
                pass
            else:
                print(f'New file to consider: {entry}')

        # From capinfo file
        metadata['Citation'] = 'Stratosphere Laboratory Dataset ' + metadata['Name'] + '. ' + metadata['Start'] + '. Stratosphere Laboratory.'

        # Store metadata in a file
        #print(metadata)
        outputfile = os.path.join(args.createfrom, 'README.json')
        of = open(outputfile, 'w')
        metadatajson = json.dump(metadata, of)



















