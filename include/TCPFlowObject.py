import subprocess

class TCPFlowObject:
    """Represents a flow that has been extracted from a provided network capture.
    This is instantiated each time a new flow is detected, and further associated
    data that has been extracted will get added to the instance. It also creates
    a global  in which flows will be stored"""

    def __init__(self, flow_id):
        """Object constructor, requiring only the tcp stream number"""
        self.flow_id = flow_id

    def getFlowIDBySourceIP(self, ip_src_to_search):
        """Returns the flow(s) that have the specified IP source"""
        #TBD
        flowID = ""
        return flowID

    def getFlowIDByDestIP(self, ip_dst_to_search):
        """Returns the flow(s) that contain the specified IP source"""
        flowID = ""
        return flowID
        
    def getIPinfo(self, ip):
        """Uses iptracer to obtain information about the provided IP.
        This assumes that the ip-tracer tool is installed (please see
        the README for details, in the "Prerequisites" section)
        Returns a dictionary containing all findings"""
        
        # Initialize a dictionary that will store the data associated with the 
        # provided IP address
        _ipInfo = dict()
        
        # This solution is far from elegant, and relying strictly on parsing
        # stdout from another tool is a bit risky, but for now it'll do. 
        # Some unit tests must be implemented for this method, in case future
        # ip-tracer updates will change it's functionality
        # -> First, we get the output "chunk", but by skipping the first 15 lines
        #    which make up for the tool's logo
        _rawdata = subprocess.run(['ip-tracer -t %s | tail -n +16' % ip], stdout=subprocess.PIPE, shell=True)

        _textbuff = _rawdata.stdout.decode('utf-8')
        # Now, we need to do some cleanup in order to end up with a usable dataset.
        # We also split the output by the newline character.
        _textbuff.replace('\x1b[01;33m','').replace('\x1b[01;37m','').replace('\x1b[01;32m','').replace('\x1b[00m','').split('\n')
        
        # Make sure no blank elements are present in our list
        _textbuff = list(filter(None, _textbuff))
        
        # Next, we go through each element in the 'ip-tracer_output' array and 
        # split it by a delimiter made up of seven whitespace chars. Each resulting 
        # string pair will eventually become key & value entries in the _ipInfo dict.
        # strip() is used to get rid of whitespaces at both ends of each item
        for field in _textbuff:
            (key, value) = field.split('>')
            _ipInfo[key.strip()] = value.strip()
            
        # Return the dictionary containing all extracted information
        return _ipInfo
        
