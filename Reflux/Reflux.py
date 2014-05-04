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

import argparse
import burplogs
import sqlite3

def processFile(sFile):
    
    print("[i] Processing " + sFile)
    blogs = burplogs.burplogs(sFile)

    fileCSV = None
    fileSQL = None
    sqlConn = None
    sqlCursor = None

    if args.csv:
        try:
            fileCSV = open(args.csv, "w")
            print("[i] Opened: " + args.csv + " for CSV output")
        except:
            print("[!] Can't open " + args.csv)
            return False
    else:
        try:
            fileCSV = open(blogs.sha2 + ".csv" , "w")
            print("[i] Opened: " + blogs.sha2 + ".csv" + " for CSV output")
        except:
            print("[!] Can't open " + blogs.sha2 + ".csv")
            return False
    
    if args.sqllite:
        try:
            sqlConn = sqlite3.connect(args.sqllite)
            print("[i] Opened: " + args.sqllite+ " for SQLLite output")

        except:
            print("[!] Can't open " + args.csv)
            return False
    else:
        try:
            sqlConn = sqlite3.connect(blogs.sha2 + ".db")
            sqlCursor = sqlConn.cursor()
            print("[i] Opened: " + blogs.sha2 + ".db" + " for SQLLite output")
            sqlCursor.execute('''CREATE TABLE burplog (time text, IP text, method text, URL text, reqURL text, responsecode text)''')
            print("[i] Created table")
        except:
            print("[!] Can't open " + blogs.sha2 + ".db")
            return False

    if blogs.process() is False:
        print("[!] Error processing")
    else:
        print("[i] Completed processing - writing to files - number of entries: " + str(len(blogs.lstObjs)))

        for lstObj in blogs.lstObjs:
            # Screen
            # print (lstObj.sTime + "," + lstObj.sIP + "," + lstObj.sMethod + "," + lstObj.sURL + "," + lstObj.sResponseCode)
            
            # CSV
            if fileCSV is not None:
                fileCSV.write (lstObj.sTime + "," + lstObj.sIP + "," + lstObj.sMethod + "," + lstObj.sURL + ","+ lstObj.sReqURL + "," + lstObj.sResponseCode + "\n")

            # SQLLite
            if sqlCursor is not None:
                sqlCursor.execute("INSERT INTO burplog VALUES (?,?,?,?,?,?)",(lstObj.sTime,lstObj.sIP,lstObj.sMethod,lstObj.sURL,lstObj.sReqURL,lstObj.sResponseCode))
                sqlConn.commit()

    # Tidy
    if fileCSV is not None:
        fileCSV.close()
    if sqlConn is not None:
        sqlConn.close()
    
    print("[i] All output written - number of entries: " + str(len(blogs.lstObjs)))

if __name__ == '__main__':
    
    print("[i] NCC Group burp proxy log reflux conversion tool - https://github.com/nccgroup")

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Input Burp log filename',required=False, type=str)
    parser.add_argument('-c', '--csv',help='Output CSV filename', required=False, type=str)
    parser.add_argument('-s', '--sqllite',help='Output SQLLite filename', required=False, type=str)
    args = parser.parse_args()


    if args.file:
        print("[i] Filename provided " + args.file);
    else:
        print("[i] No filename provided");
        args.file="C:\\Users\\Ollie\\Desktop\\BURPLogDay1";

    processFile(args.file);






