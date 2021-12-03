#!/usr/bin/env python3
#rDNS sweeps and initial enumeration for internal penetration tests
#author: Cr1ms3nRav3n
#version: 1.0

import sys
import os
import subprocess
import nmap
import argparse
import stat
from termcolor import colored
from subprocess import call
from os.path import exists

#chmod on subnet.sh dependent script
os.chmod('scripts/subnet.sh', stat.S_IEXEC)

#create directories for output hosts and ports
if not os.path.exists('output'):
	os.mkdir('output')
if not os.path.exists('output/hosts'):
	os.mkdir('output/hosts')
if not os.path.exists('output/ports'):
	os.mkdir('output/ports')

#define nmap
nm = nmap.PortScanner()
nma = nmap.PortScannerAsync()
#Define Example useage:
example_text = '''example:

 python3 valkyrie.py --rdns --subnets '10.0.0.0/8, 172.16.0.0/12'
 python3 valkyrie.py --rdns --pingsweep
 python3 valkyrie.py --nmap --ports 80 443 445 3389 --nmapargs="-f -sV"'''
 
#define arguments
parser = argparse.ArgumentParser(description='Tool to enumerate private networks.', epilog=example_text, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--rdns", help="Perform rDNS sweeps of private subnets", action="store_true")
parser.add_argument("--pingsweep", help="Perform ping sweeps of enumerated subnets. Uses subnets.txt under the output folder.", action="store_true")
parser.add_argument("--nmap", help="Perform nmap scans of enumerated hosts. Uses hosts.txt under the output folder. Flags are -Pn -sS -vv", action="store_true")
parser.add_argument("--exclusions", help="Path to file containing exclusions for nmap scans. Default is exclusions.txt", default="exclusions.txt", action="store", type=str)
parser.add_argument("--subnets", help="Subnets to sweep in rDNS sweeps", default="10.0.0.0/8", action="store", type=str)
parser.add_argument("--nmapargs", help="Arguments for nmap scan", default="-Pn -sS -vv --excludefile exclusions.txt", action="store", type=str)
parser.add_argument("--ports", nargs='+', help="Ports to check nmap scan for and output files containing live hosts.", default=(21, 80, 443, 445), action="store", type=int)
args, leftovers = parser.parse_known_args()
	
#print banner
b= open ('banner.txt', 'r')
print(colored(''.join([line for line in b]),'blue')) 

#Check for exclusions.txt.
rdnssubs = args.subnets	
file = args.exclusions
file_exists = exists(file)
if file_exists == True:
	print()
else:
	text = args.exclusions + " does not exist. Please create the file and try again."
	print()
	print(colored(text, "red"))
	exit()

def rdns_sweep():	

	print (colored('Starting rDNS sweeps, this could take a while...','blue'))
	
	args = "-sL -R --excludefile {}".format(file)
	
	#Perform RDNS sweeps on private subnets with nmap and write to file output/rdns.txt
	nm.scan(hosts=rdnssubs, arguments=args)
	f = open('output/hosts.txt', "w")
	g = open('output/rdns.txt', 'w')
	for host in nm.all_hosts():
		hostname = nm[host].hostname()
		if hostname != '':
			print (host, file=f)
			print (host, nm[host].hostname(), file=g)
	f.close()
	g.close()

	print()
	print(colored('rDNS sweeps done!', 'blue'))

	print()
	print(colored('Creating list of subnets to sweep...', 'blue'))
	
	#Calls bash script to grep the rdns.txt file and ouput a list of subnets with live hosts
	call("scripts/subnet.sh")			

	print()
	print(colored('Initial enumeration done, check output folder for RDNS records and enumerated subnets with live hosts.', 'blue'))
		
def pingsweep():
	
	file = 'exclusions.txt'
	print()
	print(colored('Sweeping enumerated subnets...', 'blue'))
	print()

	#ICMP ping sweep of enumerated subnets
	sweep = open('output/subnets.txt', 'r')
	lines = sweep.readlines()
	arg2 = "-sn -n -PE --excludefile {}".format(file)


	for line in lines:
		output = 'output/hosts/'+line.strip()+'.txt'
		f = open(output, 'w+')
		subnet=line.strip()+'.0/24'
		text = "Sweeping " + subnet
		print(colored(text, 'blue'))
		nm.scan(hosts=subnet, arguments=arg2)			
		for host in nm.all_hosts():
			status = nm[host].state()
			if status == 'up':
				print(host, file=f)
		f.close()
		
	print()
	print(colored("Pingsweeps completed! Check output/hosts/ for files", 'blue'))
	
def hostbyport():
	for port in args.ports:
		for host in nm.all_hosts():
			#Check for Hosts by Port
			try:
				if nm[host]['tcp'][port]['state'] == 'open':
					hbp = 'output/ports/'+str(port)+'.txt'
					f = open(hbp, 'a+')
					print(host, file=f)
					f.close()
			except:
				pass		
		
def nmaprnd1():
	
	print()
	directory = r'output/hosts'
	for filename in os.listdir(directory):
	
		hosts = "output/hosts/" + filename	
		with open(hosts) as f:
			Lines = f.readlines()
			print(colored('Performing nmap scans, this could take an even longer while...','blue'))
			for line in Lines:
				n = open('output/nmaprnd1.txt', 'a+')
				nm.scan(line, arguments=args.nmapargs)
				for host in nm.all_hosts():
					print ('', file=n)
					print('Host : %s (%s)' % (host, nm[host].hostname()), file=n)
					for proto in nm[host].all_protocols():
						print('------------------------', file=n)

						lport = nm[host][proto].keys()
						#lport.sort()
						for port in lport:
							print ('port: %s\nstate: %s \nname: %s \nproduct: %s \nversion: %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name'], nm[host][proto][port]['product'], nm[host][proto][port]['version']), file=n)
							print('', file=n)
							
				hostbyport()
				n.close()
				
	print('')
	print(colored("Nmap scans complete! Check nmaprnd1.txt for full scan results. Hosts by port can be found under output/ports",'blue'))																			

if args.rdns and args.pingsweep == False and args.nmap == False:

	rdns_sweep()
	
if args.pingsweep and args.rdns == False and args.nmap == False:

	pingsweep()
	
if args.nmap and args.rdns == False and args.pingsweep == False:

	nmaprnd1()	
	
if args.rdns and args.pingsweep and args.nmap == False:
	
	rdns_sweep()
	pingsweep()
	
if args.rdns and args.nmap and args.pingsweep:
	
	rdns_sweep()
	pingsweep()
	nmaprnd1()
	
if args.nmap and args.pingsweep and args.rdns == False:

	pingsweep()
	nmaprnd1()
	
if args.rdns and args.nmap and args.pingsweep == False:

	print("--nmap won't work without --pingsweep")
		
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit()
