class TCPStreamCatcher:
    """Used for extracting information from network captures"""

    def __init__(self, pcap_path):
        """Object constructor for the TCP stream extractor"""
        self.dummy = "dumdum"
        self.trace_path = pcap_path
