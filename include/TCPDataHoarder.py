from TsharkExtraction import TSharkExtraction
from TCPStreamCatcher import TCPStreamCatcher
class TCPDataHoarder:
    def __init__(self, pcap_list):
        # Store the path to the pcap that's going to be analyzed
        self.pcaps = pcap_list

    def extract_pcap_info(self):
        # For each pcap in the list, instantiate a StreamCatcher object (a "worker") that starts
        extractor = TCPStreamCatcher()
