#timout for request

import argparse
import random
import requests
from main import iot
parser = argparse.ArgumentParser(description="ST~ Tool /bahaabdelwahed")
parser.add_argument("-s","--show",action="store_true",help="Show devices ")
parser.add_argument("--add",help="Add new device ")
parser.add_argument("--scan",help="scan devices [ports,cve,upnp,mqtt]")
parser.add_argument("--id",help="id of device [or all]")
parser.add_argument("--search",help="search in exploitdb for poc [cve,fd]]")
parser.add_argument("--bug",help="filtre by vuln type[RCE,XSS...]")
parser.add_argument("--firmware",help="add firmware ")
parser.add_argument("--type",help="add device type")
parser.add_argument("--detect",action="store_true",help="detect device market[only cam]")
parser.add_argument("--tty",action="store_true",help="show serial devices")
parser.add_argument("--uart",help="Uart shell [/dev/ttyUSB0:9200]")

parser.add_argument("--fz",help="Fuzzing for API [used with --id]")
ss =requests.Session()
args=parser.parse_args()
import sys
if(len(sys.argv)<2):
    exit(1)
device1 = iot()
id = random.randint(100000,999999)
id=str(id)
if(args.add):
 device1.ADDDevice("_-_",id,args.add)
 exit(1)
if(args.show):
 device1.show()
if (args.scan):
 if args.scan == "ports" and args.id == "all":
     device1.scanner_all_devices()
     exit(1)
 if args.scan =="ports" and args.id !="all":
     device1.scan_specific_device(args.id)
     exit(1)

if(args.detect =="1"):
    if(args.id == "all"):

        device1.detect_all_devices()
        exit(1)
    else:
     if(args.id):
        device1.detect_specific_device(args.id)
        exit(1)
if(args.type):
    if(args.id != "all") and (args.id):
        device1.add_type(args.id,args.type)
if(args.firmware):
    if(args.id != "all")and (args.id):
        device1.add_firmware(args.id,args.firmware)
if(args.scan == "cve") and (args.id):
    if(args.id != "all"):
      if(args.bug):
          device1.filter(args.id, args.bug)
      else:
          device1.cve_search(args.id)
if(args.scan =="upnp") and (args.id):
    if (args.id != "all"):
        device1.nmap(args.id)
if(args.scan =="mqtt") and (args.id):
    if (args.id != "all"):
        device1.mqtt(args.id)
if(args.search =="cve" and args.id):
    device1.exploits(args.id)

if(args.search =="fd" and args.id):
    device1.exploits2(args.id)

if (args.fz):

    if(args.id):
     device1.fuzzing(args.fz,args.id)
    else:
        print("--id <id> not found [all not work here]" )
