#!/usr/bin/env python3
# rDNS sweeps and initial enumeration for internal penetration tests
# author: Cr1ms3nRav3n & Dirkenhymer
# version: 1.2

import sys
import socket
import nmap
import argparse
import stat
import os
import subprocess
import xml.etree.ElementTree as ET
from colorama import init, Fore, Back, Style
from os.path import exists

#===============Define functions===============#

#-----RDNS SWEEPS-----
#Description: Run reverse dns sweeps on target subnets. Creates a file called rdns.xml or rdns_single.xml.
#Parameters: Takes a string of a subnet structured _._._._/# ex: 192.168.10.0/24
#Returns: Returns a nothing.
def rdnssweeps(targetSubnet):
    print(Style.BRIGHT + Fore.BLUE + '\n======Starting RDNS Sweeps======\n')

    if args.full == True:
        subprocess.popen(['nmap','-sL','-R','-iL','files/subnets.txt','-oX','rdns.xml', '-v0'])
        print("We are here")
    if args.single == True:
        subprocess.call(['nmap','-sL','-R',targetSubnet,'-oX','rdns.xml','-v0'])

    print(Style.BRIGHT + Fore.BLUE + '\n======RDNS Sweeps complete!======\n')

#-----EXTRACT SUBNETS-----
#Description: Function will parse xml created from an nmap rdns scan and extract the hosts with DNS records.
#Parameters: Takes a string formatted as a path to a xml file.
#Returns: Returns a list of host IPs with dns records.
def extractsubnets(nmapFile):
    print(Style.BRIGHT + Fore.BLUE + '\n======Parsing nmap XML file======\n')
    
    #Create tree from XML file 
    tree = ET.parse(nmapFile)
    
    #Get pretty magic list
    root = tree.getroot()
    
    validHosts = []
    
    #Pull resolved hosts
    for host in root.findall('./host/[hostnames]'):
       validHosts.append(host[1].get('addr'))  
            
    print(Style.BRIGHT + Fore.BLUE + '\n======Finished parsing the file, up up and away!======\n')   
    return validHosts

#-----GET UNIQUE SUB-----
#Description: Parses given IP addresses to get the unique subnets they fall under.
#Parameters: Takes a list of host IP addresses.
#Returns: Returns a list of unique IP subnets for the given IPs.
def getuniqsub(hostAddresses):
    splitIP = ""
    subId = ""
    addedSubIds = []
    subnetList = []
    
    for host in hostAddresses:
        splitIP = host.split('.')
        subId = '.'.join(splitIP[0:3])
        if subId not in addedSubIds:
            addedSubIds.append(subId)
            
    for host in addedSubIds:
        subnetList.append(host + '.0')
        
    return subnetList      

#-----PING SWEEP-----
#Description: This method will use nmap to ping sweep the given subnets. It will create a file with "up" hosts. EX: 192.168.10.0.txt
#Parameters: Takes a list of subnet IP addresses
#Returns: Returns nothing
def pingsweep(subnets):
    file = 'exclusions.txt'
    print(Style.BRIGHT + Fore.BLUE + '\n======Sweeping enumerated subnets...====== \n')

    # ICMP ping sweep of enumerated subnets
    arg2 = "-sn -n -PE --excludefile {}".format(file)

    for subnet in subnets:
        output = 'output/hosts/' + subnet + '.txt'
        hostfile = open(output, 'w+')
        print(Style.BRIGHT + Fore.BLUE + "\n======Sweeping " + subnet + '======\n')
        cidr = subnet + '/24'
        nm.scan(hosts=cidr, arguments=arg2)
        for host in nm.all_hosts():
            status = nm[host].state()
            if status == 'up':
                print(host, file=hostfile)
        hostfile.close()

    print(Style.BRIGHT + Fore.BLUE + "\n======Pingsweeps completed! Check output/hosts/ for files======\n")

#-----HOST BY PORT-----
#Description: uses namp to scan the given ports on hosts scanned with the nm module 
#Parameters: Takes a list of port numbers to scan
#Returns: Returns nothing    
def hostbyport(ports):
    for port in ports:
        for host in nm.all_hosts():
            # Check for Hosts by Port
            try:
                if nm[host]['tcp'][port]['state'] == 'open':
                    hbp = 'output/ports/' + str(port) + '.txt'
                    f = open(hbp, 'a+')
                    print(host, file=f)
                    f.close()
            except:
                pass

#-----NMAP ROUND 1-----
#Description: 
#Parameters: Takes a string of nmap arguments, and a string of ports.
#Returns: Returns nothing
def nmaprnd1(nmapArguments,portslist):
    directory = r'output/hosts'
    dir = os.listdir(directory)
    if len(dir) == 0:
        print(Style.BRIGHT + Fore.RED + '\n======No hosts in output/hosts, please run --pingsweep first!======')
        exit()
    else:
        print(Style.BRIGHT + Fore.BLUE + '\n======Performing initial nmap scans, this could take a bit...======')
        for filename in os.listdir(directory):
            hosts = "output/hosts/" + filename
            with open(hosts) as f:
                Lines = f.readlines()
                for line in Lines:
                    n = open('output/nmaprnd1.txt', 'a+')
                    nm.scan(line, arguments=nmapArguments)
                    for host in nm.all_hosts():
                        print('', file=n)
                        print('Host : %s (%s)' % (host, nm[host].hostname()), file=n)
                        for proto in nm[host].all_protocols():
                            print('------------------------', file=n)

                            lport = nm[host][proto].keys()
                            # lport.sort()
                            for port in lport:
                                print('port: %s\nstate: %s \nname: %s \nproduct: %s \nversion: %s' % (
                                port, nm[host][proto][port]['state'], nm[host][proto][port]['name'],
                                nm[host][proto][port]['product'], nm[host][proto][port]['version']), file=n)
                                print('', file=n)

                    hostbyport(portslist)
                    n.close()

    print(Style.BRIGHT + Fore.BLUE + "\n======Nmap scans complete! Check nmaprnd1.txt for full scan results. Hosts by port can be found under output/ports======")

#-----SMB CHECK-----
#Description: Uses nmap to check for SMB Signing on hosts in the "445.txt" file. Creates two files, "smbnotenforced.txt" and "smbenforced.txt"
#Parameters: Takes Nothing
#Returns: Returns Nothing
def smbcheck():
    file = 'output/ports/445.txt'
    file_exists = exists(file)
    if file_exists == False:
        print(Style.BRIGHT + Fore.RED + '\n======445.txt does not exist! Please run --nmap first!======')
        exit()

    smbfile = open('output/ports/445.txt', 'r')
    Lines = smbfile.readlines()
    print(Style.BRIGHT + Fore.BLUE + '\n======Checking hosts for SMB signing======')
    for line in Lines:
        try:
            nm.scan(line, arguments='-p 445 --script smb2-security-mode')
            cleaned = line.strip()
            signing = nm[cleaned]['hostscript']
            clean = str(signing)
            result = ('\n' + cleaned + ' - ' + clean)
            disabled = ("Message signing enabled but not required")
            if disabled in result:
                d = open('output/smbnotenforced.txt', 'a+')
                print(cleaned, file=d)
            else:
                e = open('output/smbenforced.txt', 'a+')
                print(cleaned, file=e)
        except (KeyError):
            print(Style.BRIGHT + Fore.RED + Back.YELLOW + "KeyError! You may need to check signing manually!")
            pass


    print(Style.BRIGHT + Fore.BLUE + '\n======SMB Signing checks complete! Check output/ for results!======')        

# define nmap
nm = nmap.PortScanner()
nma = nmap.PortScannerAsync()

# Define Example useage:
example_text = '''example:
 python3 valkyrie.py --rdns --full --nmap --ports 80 443 445 3389 --nmapargs="-f -sV"'''

# define arguments
parser = argparse.ArgumentParser(description='Tool to enumerate private networks.', epilog=example_text,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--pingsweep",
                    help="Perform ping sweeps of enumerated subnets. Uses subnets.txt under the output folder.",
                    action="store_true")
parser.add_argument("--nmap",
                    help="Perform nmap scans of enumerated hosts. Uses hosts.txt under the output folder. Flags are -Pn -sS -vv",
                    action="store_true")
parser.add_argument("--exclusions", help="Path to file containing exclusions for nmap scans. Default is exclusions.txt",
                    default="exclusions.txt", action="store", type=str)
parser.add_argument("--nmapargs", help="Arguments for nmap scan", default="-p 21,25,80,443,445 --excludefile exclusions.txt",
                    action="store", type=str)
parser.add_argument("--ports", nargs='+', help="Ports to check nmap scan for and output files containing live hosts.",
                    default=(21, 25, 80, 443, 445), action="store", type=int)
parser.add_argument("--subnet", help="Target subnet for RDNS single sweep", action="store", type=str)
parser.add_argument("--smb", help="Check SMB signing on hosts with port 445 open", action="store_true")
parser.add_argument("--rdns", help="Run reverse DNS sweeps on private subnet ranges", action="store_true")
parser.add_argument("--full", help="Run RDNS Sweeps against all private network ranges", action="store_true")
parser.add_argument("--single", help="Run RDNS Sweeps against targeted subnet, use --subnet to specify", action="store_true")
args = parser.parse_args()		

#Main script
#start colorama
init()

#define nmapFile
nmapFile = 'rdns.xml'

# print banner
b = open('banner.txt', 'r')
print(Style.BRIGHT + Fore.BLUE + ''.join([line for line in b]))

# create directories for output hosts and ports
if not os.path.exists('output'):
    os.mkdir('output')
if not os.path.exists('output/hosts'):
    os.mkdir('output/hosts')
if not os.path.exists('output/ports'):
    os.mkdir('output/ports')
    
# Check for exclusions.txt.
file = args.exclusions
file_exists = exists(file)
if file_exists == False:
    print(Style.BRIGHT + Fore.RED + args.exclusions + " does not exist. Please create the file and try again.")
    exit()

if args.rdns == True:
    rdnssweeps(args.subnet)

if args.pingsweep == True:
    pingsweep(getuniqsub(extractsubnets(nmapFile)))

if args.nmap == True:
    nmaprnd1(args.nmapargs,args.ports)

if args.smb == True:
    smbcheck()

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit()
