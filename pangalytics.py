#! /usr/bin/python3

##########################################
#
#             PANGalytics
#
#  PaloAlto NextGen Analytics Toolset
# #    #    #    #    #    #    #    #
# Analysis tool will generate statistics
# about objects within PAN-OS.
#
# [*] Address Object Analytics
# [*] NAT Policy Analytics
# [*] SEC Policy Analytics
#
##########################################



import sys
from termcolor import colored, cprint
import pyfiglet
import math
import getpass
import requests.packages.urllib3
import xml.etree.ElementTree as ET
import texttable as tt
requests.packages.urllib3.disable_warnings()



# Init driver
#########################################################################
def init():
    # Display title
    cliInit()
    # input NGFW URL
    fw = selectNGFW()
    # Authenitcate with NGFW
    print ("\n")
    cprint('[*] AUTHENTICATE', 'blue')
    usr = getUser()
    pas = getPass()
    auth(fw, usr, pas)
    selectMenu(fw, usr, pas)


#########################################################################
'''
+-------------------+--------+-----------+-------+-------+-----+-----+------+
|   Address         | Events | Bytes     | Allow | Block | TCP | UDP | ICMP |
+===================+========+===========+=======+=======+=====+=====+======+
| 208.84.176.5      | 100    | 40752     | 28%   | 72%   | 12% | 86% | 00%  |
+-------------------+---------+------------+-------+-------+-----+-----+------+
| 154.27.84.2       | 0      | 0         | 00%   | 00%   | 00% | 00% | 00%  |
+-------------------+---------+------------+-------+-------+-----+-----+------+
| 208.84.176.6      | 100    | 9686      | 00%   | 100%  | 00% | 00% | 00%  |
+-------------------+---------+------------+-------+-------+-----+-----+------+

'''
# addrAnalytics
###############################################
def addrAnalytics(fw, usr, pas):
    key = getKey(fw, usr, pas)
    path = getFile()
    numLog = getNumLog()
    print ("-----------------------------------------------------------------------------")
    print ("|   Address         | Events | Bytes     | Allow | Block | TCP | UDP | ICMP |")
    cprint ('+===================+========+===========+=======+=======+=====+=====+======+','blue')
    with open(path) as file:
        for line in file:
            line = line.strip() 
            p1 = Address(fw, key, line, numLog)
            p1.query.makeQuery(p1.fw, p1.key, p1.ip, p1.numlog)


# Address Object
###############################################
class Address:
    ''' The Paloalto IP Address Object '''
    def __init__(self, firewall, authenticate, address, nlog):
        self.fw = firewall
        self.key = authenticate
        self.ip = address
        self.numlog = nlog
        self.query = self.Query()

    class Query:

        # Request Query for Address
        ############################
        def makeQuery(self, ngfw, key, ip, numlog):
            # variables
            count, qBytes, qAllow, qBlock = 0, 0, 0, 0
            iter, qOTHER, qTCP, qUDP, qICMP = 0, 0, 0, 0, 0
            # make a query with a filter, get queryID
            filter = "((addr.src eq '"+ip+"')OR(addr.dst eq '"+ip+"'))"
            cmd_src = "/api/?type=log&log-type=traffic&nlogs="+numlog+"&query="
            query_url = ngfw+cmd_src+filter+"&key="+key
            jobResp = requests.get(query_url, verify=False)
            jobRoot = ET.fromstring(jobResp.content)
            queryID = jobRoot[0][1].text
            # fetch query result by queryID
            cmd_get = "/api/?type=log&action=get&jobid="
            get_url = ngfw+cmd_get+queryID+"&key="+key
            resp = requests.get(get_url, verify=False)
            root = ET.fromstring(resp.content)
            # get event count per query
            logs = root[0][1][0].attrib
            count = int(logs.get('count'))
            # iterate all events in query
            for num in range(count):
                # byte stats
                bytes = int(root[0][1][0][iter][61].text)
                qBytes = qBytes + bytes
                # action stats
                action = root[0][1][0][iter][49].text
                if action == 'allow' or action == 'alert' or action == 'continue':
                    qAllow = qAllow + 1
                else:
                    qBlock = qBlock + 1
                # proto stats
                proto = root[0][1][0][iter][48].text
                if proto == 'icmp':
                    qICMP = qICMP + 1
                elif proto == 'tcp':
                    qTCP = qTCP + 1
                elif proto == 'udp':
                    qUDP = qUDP + 1
                else:
                    qOTHER = qOTHER + 1
                # iterate to next event
                iter = iter + 1
            tBytes = str(qBytes)
            if qAllow != 0:
                float = qAllow / count
                tAllow = str(math.trunc(float * 100))+"%"
            else:
                tAllow = str(qAllow)+"0%"

            if qBlock != 0:
                float = qBlock / count
                tBlock = str(math.trunc(float * 100))+"%"
            else:
                tBlock = str(qBlock)+"0%"

            if qTCP != 0:
                float = qTCP / count
                tTCP = str(math.trunc(float * 100))+"%"
            else:
                tTCP = str(qTCP)+"0%"

            if qUDP != 0:
                float = qUDP / count
                tUDP = str(math.trunc(float * 100))+"%"
            else:
                tUDP = str(qUDP)+"0%"

            if qICMP != 0:
                float = qICMP / count
                tICMP = str(math.trunc(float * 100))+"%"
            else:
                tICMP = str(qICMP)+"0%"

            ipspace = 17 - len(ip)
            ip += ' ' * ipspace
            tCount = str(count)
            countSpace = 7 - len(tCount)
            tCount += ' ' * countSpace
            byteSpace = 10 - len(tBytes)
            tBytes += ' ' * byteSpace
            allowSpace = 6 - len(tAllow)
            tAllow += ' ' * allowSpace
            blockSpace = 6 - len(tBlock)
            tBlock += ' ' * blockSpace
            tcpSpace = 4 - len(tTCP)
            tTCP += ' ' * tcpSpace
            udpSpace = 4 - len(tUDP)
            tUDP += ' ' * udpSpace
            icmpSpace = 5 - len(tICMP)
            tICMP += ' ' * icmpSpace


            print ("| "+ip+" | "+tCount+"| "+tBytes+"| "+tAllow+"| "+tBlock+"| "+tTCP+"| "+tUDP+"| "+tICMP+"|") 
            print ("+-------------------+--------+-----------+-------+-------+-----+-----+------+")




        # Fetch Query for Address
        ############################
        def fetchQuery(ngfw, key, jobid):
            # call for get
            cmd_get = "/api/?type=log&action=get&jobid="
            # create url for get
            get_url = ngfw+cmd_get+jobid+"&key="+key
            print (get_url)
            # fetch query result at the root
            resp = requests.get(get_url, verify=False)
            root = ET.fromstring(resp.content)
            return root

        # get event count per query
        ############################
        def getEventCount(root):
            logs = root[0][1][0].attrib
            count = int(logs.get('count'))
            return count


# Fetch result of job
###############################################
def getTrafficLog(ngfw, key, jobid):
    # call for get
    cmd_get = "/api/?type=log&action=get&jobid="
    # create url for get
    get_url = ngfw+cmd_get+jobid+"&key="+key
    print (get_url)
    # fetch query result at the root
    resp = requests.get(get_url, verify=False)
    root = ET.fromstring(resp.content)
    # get event count per query
    logs = root[0][1][0].attrib
    count = int(logs.get('count'))
    totalBytes = 0
    iter = 0
    for num in range(count):
        bytes = int(root[0][1][0][iter][61].text)
        print (bytes)
        totalBytes = totalBytes + bytes
        print (totalBytes)
        print ("********")
        iter = iter + 1


# Query Traffic Logs for IP
###############################################
def trafficQuery(ngfw, key):
    # call for query
    cmd_query = "/api/?type=log&log-type=threat&key="
    # create url for query
    query_url = ngfw+cmd_query+key
    # fetch JobID of query
    resp = requests.get(query_url, verify=False)
    root = ET.fromstring(resp.content)
    jobID = root[0][1].text
    return jobID


# Query Traffic Logs with a filter
###############################################
def queryTrafficLog(ngfw, key, ip):
    # set custom filter for ip
    filter = "((addr.src eq '"+ip+"')OR(addr.dst eq '"+ip+"'))"
    # call for query
    cmd_src = "/api/?type=log&log-type=traffic&query="
    # create url for query
    query_url = ngfw+cmd_src+filter+"&key="+key
    print (query_url)
    # fetch jobid of query
    resp = requests.get(query_url, verify=False)
    root = ET.fromstring(resp.content)
    jobID = root[0][1].text
    return jobID


# Get Path to File
###############################################
def getFile():
    print ('\n')
    cprint('[*] Path to File', 'blue')
    path = input('Path: ')
    return path

# Get number for log limit
##############################################
def getNumLog():
    print ('\n')
    cprint('[*] Select Log Limit (1-5000)', 'blue')
    numLog = input('Log#: ')
    return numLog


# Initialize CLI for Pangalytics
##############################################
def cliInit():
    print (pyfiglet.figlet_format("\nPANGalytics"))
    cprint("#"*56, 'blue')
    print ("\n\n\n\n")
    print ("  PAN-OS API library to assist in analysis of:")
    print ("Sec & Nat Rules, IP-Objectss, App-IDs, User-IDs")
    print ("\n\n\n\n")


# Select Firewall
###############################################
def selectNGFW():
    cprint('[*] Firewall: ', 'blue')
    choice = input("(url)")
    return choice
    if choice == "y":
        return fw
    else:
        if choice == "n":
            fw = input("[*] Firewall: ")
            return fw
        else:
            quit()


# getUser
###############################################
def getUser():
    username = input('Username: ')
    return username


# getPass
###############################################
def getPass():
    password = getpass.getpass()
    return password


# Authenticate using Paloalto API
###############################################
def auth(fw, usr, pas):
    print ('\n')
    var = 0
    while var == 0:
        token = getKey(fw, usr, pas)
        if token == 'Invalid credentials.':
            print ("Invalid credentials, please try again")
        else:
            print ("Success!")
            var = 1
        return token


# Get API Key with credentials
###############################################
def getKey(ngfw, usr_name, usr_pass):
    # call for keygen
    cmd_keygen = "/api/?type=keygen"
    # create url for requesting a Key  API
    key_url = ngfw+cmd_keygen+"&user="+usr_name+"&password="+usr_pass
    # fetch key using url
    resp = requests.get(key_url, verify=False)
    root = ET.fromstring(resp.content)
    key = root[0][0].text
    return key


# selectMenu
###############################################
def selectMenu(fw, usern, passw):
    loop=True
    while loop:          ## While loop which will keep going until loop = False
        print ("\n")
        print (" "+10 * "-" + " Pangalytics " + 11 * "-")
        print (" "+11 * "-" + "   MENU "+15 * "-"+"\n")
        print (" [1] Address Object Analytics\n")
        print (" [2] NAT Policy Analytics\n")
        print (" [3] SEC Policy Analytics\n")
        print (" [4] Exit\n")
        print (" "+34 * "-")
        choice = input(" Enter your choice [1-4]: ")
        if choice == '1':
            addrAnalytics(fw, usern, passw)
        elif choice == '2':
            print ("Menu 2 has been selected")
        elif choice == '3':
            print ("Menu 3 has been selected")
        elif choice == '4':
            print ("\n\n\n\t/Quitting Pangalytics/\t\n\n\n")
            loop=False
        else:
            print ("Wrong option selection. Enter any key to try again..")
    exit 




"""
[*] Resources

    https://extr3metech.wordpress.com/2014/09/14/simple-text-menu-in-python/
    https://stackoverflow.com/questions/39032720/formatting-lists-into-columns-of-a-table-output-python-3

"""

def main():
    init()


if __name__ == '__main__':
    main()


