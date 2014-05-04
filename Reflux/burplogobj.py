#
# Reflux for Burp log parsing and conversion
# 
# Released as open source by NCC Group Plc - http://www.nccgroup.com/
# 
# Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com
#
# http://www.github.com/nccgroup/burp-reflux
#
# Released under AGPL see LICENSE for more information
#

class burplogobj(object):
    """NCC Group Burp WebProxy log parser entry object"""

    def __init__(self):
        print("[i] Burplogs object class initialized");

    # Header
    sHDRRAW = ""
    sTime = ""
    sURL = ""
    sIP = ""

    # Request
    lstReqRAW = ""
    sMethod = ""
    sReqURL = ""
    sVer = ""

    # Request
    lstRespRAW = ""
    sResponseCode = ""

    def __init__(self):
         # Header
        self.sHDRRAW = ""
        self.sTime = ""
        self.sURL = ""
        self.sIP = ""

        # Request
        self.lstReqRAW = ""
        self.sMethod = ""
        self.sURL = ""
        self.sVer = ""
    
        # Request
        self.lstRespRAW = ""
        self.sResponseCode = ""

    # http://stackoverflow.com/questions/5160077/encoding-nested-python-object-in-json
    def reprJSON(self):
        return dict(sTime=self.sTime, sURL=self.sURL)

