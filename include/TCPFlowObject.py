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