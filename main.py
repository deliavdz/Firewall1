from netfilterqueue import NetfilterQueue
from scapy.all import TCP, UDP, IP
from scapy.all import *
import time
import json

try:
    file = open("rules.json")
    info = json.load(file)
    file.close()

#banned IP addresses
    if("ListOfBannedIpAddr" in info):
        if(type(info["ListOfBannedIpAddr"])==list):
            ListOfBannedIpAddr = info["ListOfBannedIpAddr"]
        else:
            print("There is not a valid list of banned IP addresses. Default to empty list")
            ListOfBannedIpAddr = []
    else:
        print("There is not a list of banned IP addresses. Default to empty list")
        ListOfBannedPorts = []

#banned ports
    if("ListOfBannedPorts" in info):
        if(type(info["ListOfBannedPorts"])==list):
            ListOfBannedPorts = info["ListOfBannedPorts"]
        else:
            print("There is not a valid list of banned ports. Default to empty list")
            ListOfBannedPorts = []
    else:
        print("There is not a list of banned ports. Default to empty list")
        ListOfBannedPorts = []

##banned prefixes
    if("ListOfBannedPrefixes" in info):
        if(type(info["ListOfBannedPrefixes"])==list):
            ListOfBannedPrefixes = info["ListOfBannedPrefixes"]
        else:
            print("There is not a valid list of banned prefixes. Default to empty list")
            ListOfBannedPrefixes = []
    else:
        print("There is not a list of banned prefixes. Default to empty list")
        ListOfBannedIpAddr = []
    
#time
    if("TimeThreshold" in info):
        if(type(info["TimeThreshold"])==int):
            TimeThreshold = info["TimeThreshold"]
        else:
            print("Invalid Time threshold in rule file- defaulting to 10")
            TimeThreshold = 10
    else:
        print("Time threshold missing in rule file - defaulting to 10")
        TimeThreshold = 10

#packet threshold
    if("PacketThreshold" in info):
        if(type(info["PacketThreshold"])==int):
            PacketThreshold = info["PacketThreshold"]
        else:
            print("Invalid Time threshold in rule file- defaulting to 100")
            PacketThreshold = 100
    else:
        print("Time threshold missing in rule file - defaulting to 100")
        PacketThreshold = 10

#boolean ping attacks
    if("BlockPingAttacks" in info):
        if(type(info["BlockPingAttacks"])==(True or False)):
            PingAttacks = info["BlockPingAttacks"]
        else:
            print("Invalid boolean to indicate blockage of ping attacks - defaulting to true")
            PingAttacks = True
    else:
        print("No indication of blockage of ping attacks, defualt to true")
        PingAttacks = True
except FileNotFoundError:
    print("Rule file (firewallrules.json) not found, setting default values")
    ListOfBannedIpAddr = [] 
    ListOfBannedPorts = []
    ListOfBannedPrefixes = []
    TimeThreshold = 10 #sec
    PacketThreshold = 100    
    BlockPingAttacks = True

def firewall(pkt):
	req = IP(pkt.get_payload())

	if(req.src in ListOfBannedIpAddr):
		print(req.src, "is a banned IP address, it will be dropped")
		pkt.drop()
		return 
    
    if(req.haslayer(TCP)):
        port = sca.getlayer(TCP)
		if(port.dport in ListOfBannedPorts):
			print(port.dport, "is a blocked port through the firewall")
			pkt.drop()
			return
    if(req.haslayer(UDP)):
        port = sca.getlayer(UDP)
		if(port.dport in ListOfBannedPorts):
			print(port.dport, "is a blocked port through the firewall")
			pkt.drop()
			return 