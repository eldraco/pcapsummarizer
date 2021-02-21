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
        metadata['Author'] = 'Stratosphere Team'
        metadata['Contact'] = 'stratosphere@aic.fel.cvut.cz'
        metadata['Disclaimer'] = 'These files were generated in the Stratosphere Laboratory, AIC group, as part of the Aposemat Project with the support of Avast Software to collect IoT captures at the Czech Technical University, Prague, Czech Republic.'
        metadata['License'] = 'https://creativecommons.org/licenses/by/3.0/'
        metadata['URL'] = 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-150-1/'
        metadata['Password'] = "The password of the compressed file is 'infected'"


        # URL of the capture. From the name of the folder we were given for now
        # IoTDatasets/CTU-IoT-Malware-Capture-35-1
        # CTU-Malware-Capture-Botnet-278-1


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

        ## If it was malware, get malware name
        out = subprocess.Popen(["grep", "-i", "Probable Malware Name", readmefile], stdout=subprocess.PIPE)
        malwarename = ' '.join(out.communicate()[0].decode("utf-8").split()[4:])
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
        if timefirstpacket:
            metadata['Start'] = timefirstpacket

        ## Last packet time
        out = subprocess.Popen(["grep", "-i", "Last packet time:", capinfofile], stdout=subprocess.PIPE)
        timelastpacket = ' '.join(out.communicate()[0].decode("utf-8").split()[3:])
        if timelastpacket:
            metadata['End'] = timelastpacket

        ## Duration
        out = subprocess.Popen(["grep", "-i", "Capture duration:", capinfofile], stdout=subprocess.PIPE)
        timelastpacket = ' '.join(out.communicate()[0].decode("utf-8").split()[2:])
        if timelastpacket:
            metadata['Duration'] = timelastpacket

        # From each File
        metadata['Files'] = {}
        entries = os.listdir(args.createfrom)
        for entry in entries:
            if 'capinfo' in entry:
                metadata['Files']['capinfos'] = {'Description': 'Capinfos tool', 'File':entry}
            print(entry)


# dnstop: {
# Description: from dnstop tool
# }
# passivedns:  {
# Description: from passivedns tool
# }
# pcap: {
# Description: original pcap with traffic
        metadata['Files']['pcap'] = {'Description': '', 'File':''}
# }
# bro: {
# Description: folder with log files of Zeek
# LastUpdate: 2021/02/20 09:23:23.232323
# }
# suricata: {
# Description: folder with detections of Suricata IDS
# LastUpdate: 2021/02/20 09:23:23.232323
# }
# }
# Private IP of device: 192.168.1.72      (can be empty)
# Public IP of device: 147.32.82.234     (can be empty)
# Operation Comments: {
# 2021/02/23 11:23:32.342323: We rebooted the device
# }

        """

        #"Suricata run"
        # Get the IP
        out = subprocess.Popen(["grep", "-i", "Suricata run:", args.createfrom], stdout=subprocess.PIPE)
        suricataupdate = ' '.join(out.communicate()[0].decode("utf-8").split()[7:])
        if suricataupdate:
            metadata['Suricata'] = suricataupdate
        """


        # From capinfo file
        metadata['Citation'] = 'Stratosphere Laboratory Dataset ' + metadata['Name'] + '. ' + metadata['Start'] + '. Stratosphere Team.'

        # Store metadata in a file
        #print(metadata)
        outputfile = open(args.output, 'w')
        metadatajson = json.dump(metadata, outputfile)



















