class TsharkExtraction:
    """This class contains all required operations for extracting TCP stream/flow information using tshark"""
    
    def __init__(self, pcap_path, attributes_to_extract):
    """Object constructor requiring a path to a pcap/capture file."""
        self.trace = pcap_path
        self.attributes = attributes_to_extract
        
    def extractInfo(self):

        output = subprocess.run(['tshark -r %s -nn -e tcp.stream -e ip.src -e ip.dst -Tfields -E separator=\=\- -R ip -2'], stdout=subprocess.PIPE, shell=True)

        for line in output:
            flow_data = line.split('=')
            # Here, if the flow is already present in the main tcp_flows dictionary,
            # we just append the details of the current packet to the flow it belongs to.
