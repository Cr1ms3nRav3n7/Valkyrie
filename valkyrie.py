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
from termcolor import colored
from os.path import exists

#Define functions

#Run reverse dns sweeps on target subnets
def rdnssweeps(targetSubnet):
    print(colored('\n======Starting RDNS Sweeps======\n', 'blue'))

    if args.full == True:
        subprocess.call(['nmap','-sL','-R','-iL','subnets.txt','-oX','rdns.xml', '-v0'])
    if args.single == True:
        subprocess.call(['nmap','-sL','-R',targetSubnet,'-oX','rdns_single.xml','-v0'])

    print(colored('\n======RDNS Sweeps complete!======\n', 'blue'))

def extractsubnets(nmapFile):
    print(colored('\n======Parsing nmap XML file======\n', 'blue'))
    
    #Create tree from XML file 
    tree = ET.parse(nmapFile)
    
    #Get pretty magic list
    root = tree.getroot()
    
    validHosts = []
    
    #Pull resolved hosts
    for host in root.findall('./host/[hostnames]'):
       validHosts.append(host[1].get('addr'))  
            
    print(colored('\n======Finished parsing the file, up up and away!======\n', 'blue'))   
    return validHosts
    
def getuniqsub(hostAddresses):
    #Create list of subnets with live hosts from parsed XML info
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

def pingsweep(subnets):
    file = 'exclusions.txt'
    print(colored('\n======Sweeping enumerated subnets...====== \n', 'blue'))

    # ICMP ping sweep of enumerated subnets
    arg2 = "-sn -n -PE --excludefile {}".format(file)

    for subnet in subnets:
        output = 'output/hosts/' + subnet + '.txt'
        hostfile = open(output, 'w+')
        text = "\n======Sweeping " + subnet + '======\n'
        print(colored(text, 'blue'))
        cidr = subnet + '/24'
        nm.scan(hosts=cidr, arguments=arg2)
        for host in nm.all_hosts():
            status = nm[host].state()
            if status == 'up':
                print(host, file=hostfile)
        hostfile.close()

    print(colored("\n======Pingsweeps completed! Check output/hosts/ for files======\n", 'blue'))
    
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

def nmaprnd1(nmapArguments,portslist):
    directory = r'output/hosts'
    dir = os.listdir(directory)
    if len(dir) == 0:
        print(colored('\n======No hosts in output/hosts, please run --pingsweep first!======', 'red'))
        exit()
    else:
    	print(colored('\n======Performing initial nmap scans, this could take a bit...======', 'blue'))
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

    print(colored(
        "\n======Nmap scans complete! Check nmaprnd1.txt for full scan results. Hosts by port can be found under output/ports======",
        'blue'))

def smbcheck():
    file = 'output/ports/445.txt'
    file_exists = exists(file)
    if file_exists == False:
        print(colored('\n======445.txt does not exist! Please run --nmap first!======', "red"))
        exit()

    smbfile = open('output/ports/445.txt', 'r')
    Lines = smbfile.readlines()
    print(colored('\n======Checking hosts for SMB signing======', 'blue'))
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
            print(colored("KeyError! You may need to check signing manually!", "red"))
            pass


    print(colored('\n======SMB Signing checks complete! Check output/ for results!======', 'blue'))        

# define nmap
nm = nmap.PortScanner()
nma = nmap.PortScannerAsync()

# Define Example useage:
example_text = '''example:
 python3 valkyrie.py --nmap --ports 80 443 445 3389 --nmapargs="-f -sV"'''

# define arguments
parser = argparse.ArgumentParser(description='Tool to enumerate private networks.', epilog=example_text,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--extract", help="Parse XML output from RDNS sweeps for other functions", action="store_true")
parser.add_argument("--pingsweep",
                    help="Perform ping sweeps of enumerated subnets. Uses subnets.txt under the output folder.",
                    action="store_true")
parser.add_argument("--nmap",
                    help="Perform nmap scans of enumerated hosts. Uses hosts.txt under the output folder. Flags are -Pn -sS -vv",
                    action="store_true")
parser.add_argument("--exclusions", help="Path to file containing exclusions for nmap scans. Default is exclusions.txt",
                    default="exclusions.txt", action="store", type=str)
parser.add_argument("--nmapfile", help="Nmap XML file to parse", default="rdns.xml", action="store", type=str)
parser.add_argument("--nmapargs", help="Arguments for nmap scan", default="-p 21,25,80,443,445 --excludefile exclusions.txt",
                    action="store", type=str)
parser.add_argument("--ports", nargs='+', help="Ports to check nmap scan for and output files containing live hosts.",
                    default=(21, 25, 80, 443, 445), action="store", type=int)
parser.add_argument("--dns", help="DNS server to use for nmap scans", action="store", type=str)
parser.add_argument("--subnet", help="Target subnet for RDNS single sweep", action="store", type=str)
parser.add_argument("--smb", help="Check SMB signing on hosts with port 445 open", action="store_true")
parser.add_argument("--rdns", help="Run reverse DNS sweeps on private subnet ranges", action="store_true")
parser.add_argument("--full", help="Run RDNS Sweeps against all private network ranges", action="store_true")
parser.add_argument("--single", help="Run RDNS Sweeps against targeted subnet, use --subnet to specify", action="store_true")
args = parser.parse_args()		

#Main script

# print banner
b = open('banner.txt', 'r')
print(colored(''.join([line for line in b]), 'blue'))

# chmod on subnet.sh dependent script
os.chmod('scripts/subnet.sh', stat.S_IEXEC)

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
    text = args.exclusions + " does not exist. Please create the file and try again."
    print()
    print(colored( text, "red"))
    exit()

if args.rdns == True:
    rdnssweeps(args.subnet)

if args.pingsweep == True:
    pingsweep(getuniqsub(extractsubnets(args.nmapfile)))

if args.nmap == True:
    nmaprnd1(args.nmapargs,args.ports)

if args.smb == True:
    smbcheck()

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit()
