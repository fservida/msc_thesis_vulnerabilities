# pcap_parser.py
# Project: pentesting
# 
# Created by "Francesco Servida"
# Created on 17.05.18

import pyshark
import json
import argparse
import sys
from ipaddress import ip_address

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Parses PCAP file and extracts auth for QBee")
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    parser.add_argument('-v', '--verbose', help="Enable debugging output", action='store_true')
    parser.add_argument('pcap', help="Input file path", type=str)
    parser.add_argument('ip', help='IP Address of the QBee Device.', type=ip_address)
    parser.add_argument('output', help='File output (default: std out)', nargs='?',
                        type=argparse.FileType('w'), default=sys.stdout)

    args = parser.parse_args()

    # packets = pyshark.FileCapture('../data/qbee_1605.pcap', display_filter="http and ip.addr == 10.20.30.15")
    packets = pyshark.FileCapture(args.pcap, display_filter="http and ip.addr == {}".format(args.ip))

    for packet in packets:
        try:
            if packet.http.request_uri[:7] in ("/config",):
                cookie = packet.http.cookie_pair
                cookie_list = cookie.split(",")
                cookie_dict = {param.split("=")[0].strip(): param.split("=")[1].strip() for param in cookie_list}
                credentials = dict(cookie_dict, IP=str(args.ip))
                json.dump(credentials, args.output, indent=4)
                break
        except AttributeError:
            # packet is a an answer, skip
            pass
