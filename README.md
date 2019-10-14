NTP-Monlist-Amplification-Attack
================================
NTP AMPLIFICATION ATTACKS:
This script makes a MONLIST query to an NTP Server that is
vulnerable, this is done through IP spoofing and will flood
the victim with an amplified response.

In order to stop the execution of this program, press CTRL-C

#Installation
Note: This script works for Python 3.7.x or above, other versions
of Python 3 will probably work.

Make sure to install scapy library on your local machine. You
can do this by installing it through pip3 and the requirements.txt
file located in this folder.

E.g.: pip3 install -r requirements.txt

#Usage
This tool comes with a set of flags for use through the CLI,
please note that if you do not set flags you will still be
prompted for the information required.

0. -d, --debug - Enabling debug will give you information on most
of the steps, this is to be used when something is not working
properly. May or not help you with your issue, keep this in mind.
1. -t, --target - IP address of the victim host, this will be the
IP that will received the amplified attack
2. -f, --file - File that contains the NTP Servers, even if it
is only one it needs to be in a file.
3. -T, --threads - Threads that will be used for this process, this
is an optional flag as this script will figure out the amount of
threads. Probably this will be removed in the future

#Important
Please take note of the following:
1) Do not use this script for malicious purposes
2) This is for educational and instructional use only
3) Yes, the above point (2) includes Pentesting
4) Use with caution, this can bring devices down VERY easily

#TODO
1. Implement method to allow IP addresses to be sent through
the CLI as an alternative to a file.
2. Potentially remove -T flag as it is not really needed,
the script can figure out how many threads are to be run