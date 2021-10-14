#!/usr/bin/env python3
#rDNS sweeps and initial enumeration for internal penetration tests
#author: Cr1ms3nRav3n
#version: 1.0

import sys
import os
import subprocess
import nmap
import argparse
from termcolor import colored
from subprocess import call
from os.path import exists

#define nmap
nm = nmap.PortScanner()
nma = nmap.PortScannerAsync()

#define arguments
parser = argparse.ArgumentParser(description='Tool to enumerate private networks.')
parser.add_argument("--rdns", help="Perform RDNS sweeps of private subnets", action="store_true")
parser.add_argument("--pingsweep", help="Perform ping sweeps of enumerated subnets. Uses subnets.txt under the output folder.", action="store_true")
parser.add_argument("--nmap", help="Perform nmap scans of enumerated hosts. Uses hosts.txt under the output folder. Flags are -Pn -sS -vv", action="store_true")
parser.add_argument("--exclusions", help="Path to file containing exclusions for nmap scans. Default is exclusions.txt", default="exclusions.txt", action="store", type=str)
args, leftovers = parser.parse_known_args()

#print banner
b= open ('valk.txt', 'r')
print(colored(''.join([line for line in b]),'blue')) 

#Check for exclusions.txt.	
file = 'exclusions.txt'
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
	nm.scan(hosts='192.168.2.0/24', arguments=args)
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
		f = open(output, 'w')
		subnet=line.strip()+'.0/24'
		nm.scan(hosts=subnet, arguments=arg2)			
		for host in nm.all_hosts():
			status = nm[host].state()
			if status == 'up':
				print(host, file=f)
		text = "Sweeping " + subnet
		print(colored(text, 'blue'))
	print()
	print(colored("Pingsweeps completed! Check output/hosts/ for files", 'blue'))
	
def nmaprnd1():
	
	directory = r'output/hosts'
	for filename in os.listdir(directory):
	
		hosts = "output/hosts/" + filename	
		with open(hosts) as f:
			Lines = f.readlines()
			for line in Lines:
				print("Scanning", line)
				nm.scan(line, arguments="-Pn -sS -vv")
				
					
	
			

if args.rdns and args.pingsweep == False:

	rdns_sweep()
	
if args.pingsweep and args.rdns == False:

	pingsweep()
	
if args.nmap:
	nmaprnd1()	
	
if args.rdns and args.pingsweep:
	
	rdns_sweep()
	pingsweep()
		
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit()

