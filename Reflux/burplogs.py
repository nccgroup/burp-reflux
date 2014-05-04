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

import os
import sys
import burplogobj
import hashlib

class burplogs(object):
    """NCC Group Burp WebProxy log parser"""

    bFile = None
    logBuffer = None
    logBufferLen = 0
    logBufferD = None
    logBufferLenD = 0
    lstObjs = []
    sha2 = None

    def __init__(self, sFile):
        print("[i] Burplogs class initialized");
        self.lstObjs = []
        
        # Open and read the file
        try:
            # Read the entire file into memory for performance
            if os.path.exists(sFile):
                bFile = open(sFile, 'rb')
                self.logBuffer = bFile.read()

        except:
            print("[!] Couldn't open / read " + sFile + " - "  + str(sys.exc_info()[0])); 
            return False

        finally:
            if bFile is not None:
                self.logBufferLen = len(self.logBuffer)
                print("[i] File read into memory sucessfully");
                bFile.close()
            else:
                return None
        
        # Convert
        self.logBufferD = self.logBuffer.decode('ascii','ignore')
        self.logBufferLenD = len(self.logBufferD)
        self.logBuffer = None    # free memory
        self.logBufferLen = None

        hashTmp = hashlib.sha256()
        hashTmp.update(self.logBufferD.encode('utf-8'))
        self.sha2 = hashTmp.hexdigest()

    def process(self):
        print("[i] Actually processing");
        
        # Check
        if self.logBufferD is None:
            return False

        # Init
        stateNow = "RecordPending"
        iBlankCount = 0
        iLineCount = 0
        burpObj = None
        iReqLine = 0
        iRespLine = 0

        # This will loop us through
        for sLine in self.logBufferD.split('\n'):
            iLineCount+=1
            #print(sLine)

            # Start of record header
            if sLine.rstrip() == '======================================================' and stateNow == 'RecordPending':
                if burpObj is not None:
                    burpObj.lstReqRAW = lstRequest
                    burpObj.lstRespRAW = lstResponse
                    self.lstObjs.append(burpObj)
                    burpObj = None
                burpObj = burplogobj.burplogobj()
                iBlankCount = 0
                iReqLine = 0
                iRespLine = 0
                lstRequest = []
                lstResponse = []
                #print('0('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = 'RecordHdr'
                continue

            # Header value
            if stateNow == 'RecordHdr':
                burpObj.sHDRRaw = sLine

                hdrTmp = sLine.split("  ")
                if(len(hdrTmp)==3):
                    burpObj.sTime=hdrTmp[0]
                    burpObj.sURL=hdrTmp[1]
                    burpObj.sIP=hdrTmp[2][1:-2]

                #print('1('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = 'RecordEndHdr'
                continue

            # End of record header / start of request
            if sLine.rstrip() == '======================================================' and stateNow == 'RecordEndHdr':
                #print('2('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = 'RecordRequest'
                continue

            # End of request
            if sLine.rstrip() == '======================================================' and stateNow == 'RecordRequest':
                #print('3('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = 'RecordRequestEnd'
                continue
            elif stateNow == 'RecordRequest': # extract the request
                if iReqLine == 0:
                    reqTmp = sLine.split(" ")
                    if len(reqTmp) == 3:
                        burpObj.sMethod = reqTmp[0]
                        burpObj.sReqURL = reqTmp[1]
                        burpObj.sVer = reqTmp[2]

                lstRequest.append(sLine)
                iReqLine+=1
                continue

            #
            # If we've finished the request and are looking for end of record or response markers
            #
            if sLine.rstrip() == '' and stateNow == 'RecordRequestEnd' and iBlankCount < 2:
                iBlankCount+=1
                #print('4('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                continue
            elif sLine.rstrip() == '' and stateNow == 'RecordRequestEnd' and iBlankCount >= 2:
                iBlankCount+=1
                #print('4a('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = 'RecordPending'
                continue
            elif sLine.rstrip() == '' and stateNow == 'RecordResponseEnd' and iBlankCount < 2:
                iBlankCount+=1
                #print('8('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                continue
            elif sLine.rstrip() == '' and stateNow == 'RecordResponseEnd' and iBlankCount >= 2:
                iBlankCount+=1
                #print('8a('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = 'RecordPending'
                continue
            elif sLine.rstrip() == '' and stateNow == "RecordPending":
                iBlankCount+=1
                #print('-1('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                continue

            # Response body
            if sLine.rstrip() != '' and stateNow == 'RecordRequestEnd':
                #print('5('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = 'RecordResponse'
                lstResponse.append(sLine)
                resTmp = sLine.split(" ")
                if len(resTmp) == 3:
                    burpObj.sResponseCode = resTmp[1]
                continue
            elif sLine.rstrip() != '======================================================' and stateNow == 'RecordResponse':
                lstResponse.append(sLine)
                continue

            # Start of Response
            if sLine.rstrip() == '======================================================' and stateNow == 'RecordRequestEnd' and iBlankCount < 3:
                continue
            elif sLine.rstrip() == '======================================================' and stateNow == 'RecordRequestEnd' and iBlankCount == 3:
                iBlankCount=0
                #print('6('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = "RecordPending" # End of record
                continue 
            elif sLine.rstrip() == '======================================================' and (stateNow == 'RecordRequestEnd' or stateNow == 'RecordResponseEnd') and iBlankCount > 3:
                print("[!] Error - state:" + stateNow + " line:" + str(iLineCount) + " line:" + sLine.rstrip())
                return False

            # End of response
            if sLine.rstrip() == '======================================================' and stateNow == 'RecordResponse':
                #print('7('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = 'RecordResponseEnd'
                continue
            
            # End of response
            if sLine.rstrip() == '======================================================' and stateNow == 'RecordResponseEnd' and iBlankCount == 3:
                iBlankCount=0
                #print('10('+str(int(iBlankCount))+') - line:' + str(int(iLineCount)) + " state:" +stateNow + " - " + sLine,flush=True)
                stateNow = "RecordPending" # End of record
                continue

            
        logBufferD = None
        if burpObj is not None:
            self.lstObjs.append(burpObj)
            burpObj = None

        return True