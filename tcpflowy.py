#!/usr/bin/python3
import sys
import argparse
import logging

# Since a config file is used for certain parameters, it is mandatory to import
# the appropriate parsing module
from configparser import ConfigParser

### ==> CUSTOM MODULES <== ###
from include.TCPFlowObject import TCPFlowObject


def load_cfg():
    # By default, the script looks for a 'config.ini' file in the same location. If
    # specified at runtime using the --custom-cfg parameter, the path passed as 
    # argument is used for the config

    # Instantiate the ConfigParser 
    config_object = ConfigParser()

    # Load the configuration file
    config_object.read("config.ini")

    # Get the password
    userinfo = config_object["USERINFO"]
    print("Password is {}".format(userinfo["password"]))


def test_extract_info(ip_addr):
    tcp = TCPFlowObject("4")
    tcp.get_ip_info("54.239.195.47")


def main():
    # Python program to demonstrate
    # command line arguments

    # Initialize parser
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=str, help="The .pcap file to be scanned")
    parser.add_argument("-t", '--extraction-tool',
                        help="Specify which tool should be used to process the given PCAP (default:'tshark')",
                        default="tshark")
    parser.add_argument("-v", '--verbose', help="increase output verbosity", action="store_true")
    parser.add_argument("-M", '--mindmap', help="Generates a standard mindmap file with the extracted data",
                        action="store_true")
    parser.add_argument("-c", '--generate-chart', help="Generates a bar chart based on the extracted data",
                        action="store_true")
    script_args = parser.parse_args()

    if script_args.verbose:
        print("verbosity turned on")
    #print(script_args.pcap)
    test_extract_info(script_args.pcap)



if __name__ == "__main__":
    main()
