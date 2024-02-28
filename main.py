import re
import os
import pymongo
import socket
import threading
import time
import requests
import platform
import pyxploitdb
ports=[22,80,443,21,27017,10001,5555,1900,1883] #used port in iot
class iot:
    def __init__(self,host="localhost"):
        print("IDP - V 1.0")
        self.host=host
        client = pymongo.MongoClient("mongodb://localhost:27017/")
        self.db = client['IOTDev']
        self.collection = self.db['devices']
        self.cve_id = []
    def show(self):
        fd = self.collection.find()
        for data in fd:
            print("[+] {} {} {} {} {} {}".format(data["device_id"],data["device_name"],data["device_ip"],data["device_ports"],data["device_type"],data["device_firmware"]))
    def ADDDevice(self,device_name,device_id,device_ip,device_type="NOt Known"):
        self.device_name=device_name
        self.device_id=device_id
        self.device_ip=device_ip
        self.firmware = "UNKNOWN"
        self.device_ports=[""]
        self.device_type = device_type
        data = {"device_name":self.device_name,"device_id":self.device_id,"device_ip": self.device_ip,"device_ports": self.device_ports,"device_type":self.device_type,"device_firmware":self.firmware}
        self.collection.insert_one(data)
    def scanner(self,port):
        self.device_ports=[]
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
          sock.connect((self.device_ip,port))
          self.device_ports.append(port)
        except socket.error as e:
          pass
        finally:
          sock.close()
    def scanner_port(self):
     threads=[]
     try:
      for port in ports:
       th = threading.Thread(target=self.scanner,args=(port,))
       threads.append(th)
      for th in threads:
         th.start()
      for th in threads:
         th.join()
     except BaseException as e:
         d=e
    def scanner_all_devices(self):
        data = self.collection.find()
        for dt in data:
            self.device_ip=dt["device_ip"]
            self.scanner_port()
            filter = {"device_ip": str(self.device_ip)}
            update = {"$set": {"device_ports": str(self.device_ports)}}
            self.collection.update_one(filter,update)
            time.sleep(0.05)
    def get_device(self,id):
        qr = {"device_id": id}
        doc = self.collection.find(qr)
        for d in doc:
            return d
            break
    def scan_specific_device(self,id):
        doc = self.get_device(id)
        self.device_ip=doc["device_ip"]
        self.scanner_port()
        filter = {"device_ip": str(self.device_ip)}
        update = {"$set": {"device_ports": str(self.device_ports)}}
        self.collection.update_one(filter, update)
    def detect_device(self,ip):
      self.device_ip=ip
      self.scanner(80)
      if(80 in self.device_ports):
       resp = requests.get("http://"+ip+"/")
       hk_vs = requests.get("http://"+ip+"/doc/page/login.asp")
       lorex= requests.get("http://"+ip+"/baseProj/images/favicon.ico")
       fd = re.search("webplugin.exe",resp.text)
       fd2 = re.search("<title>HA Bridge</title>",resp.text)
       if(fd):
        if(fd.group()=="webplugin.exe"):
          self.device_type="Dahua - ADT"
       if(hk_vs.status_code==200):
          self.device_type = "hikvision"
       if(lorex.status_code==200):
          self.device_type = "lorex"
       if(fd):
        if(fd.group() =="<title>HA Bridge</title>"):
           self.device_type = "HA Bridge"
       else:
          self.scanner(10001)
          if(10001 in self.device_ports):
           self.device_type = "zmodo"

       filter = {"device_ip": str(self.device_ip)}
       update = {"$set": {"device_type": self.device_type}}
       self.collection.update_one(filter, update)
    def detect_all_devices(self):
        data = self.collection.find()
        for dt in data:
            self.detect_device(dt["device_ip"])
    def detect_specific_device(self,id):
        dv = self.get_device(id)
        self.detect_device(str(dv["device_ip"]))

        # self.detect_device(dv["device_ip"])
    def add_type(self,id,type):
        dv = self.get_device(id)
        self.device_ip=dv["device_ip"]
        filter = {"device_ip": str(self.device_ip)}
        update = {"$set": {"device_type": type}}
        self.collection.update_one(filter, update)
    def add_firmware(self,id,firmware):
        dv = self.get_device(id)
        self.device_ip = dv["device_ip"]
        filter = {"device_ip": str(self.device_ip)}
        update = {"$set": {"device_firmware": firmware}}
        self.collection.update_one(filter, update)
    def cve_sr(self,text):
        import requests
        import re
        res = requests.post("https://cve.circl.lu/search", data={"search": text})
        r = res.text.split(">")

        cve_summary = []
        for c in r:
            if ("title=" in c):
                cve_summary.append(c.split("title=")[1])

            if ("</a" in c):
                c = c.split("</a")[0]
                if ("CVE-" in c):
                    self.cve_id.append(c)

        for i in range(0, len(self.cve_id)):
            # print(cve_id[i] + "==> " + cve_summary[i])
            print(self.cve_id[i])


    def cve_search(self,id):
        dv = self.get_device(id)
        self.device_type=dv["device_type"]
        self.firmware=dv["device_firmware"]
        if(self.device_type!="NOt Known" ):
         print("======== {} ======".format(self.device_type))
         self.cve_sr(self.device_type)
        else:
            print("Add the device type ")
        if(self.firmware!="UNKNOWN"):
         print("======== {} ======".format(self.firmware))
         self.cve_sr(self.firmware)
        else:
            print("Add the firmware ")
    def cve_fl(self,text,key):
        import requests
        import re
        res = requests.post("https://cve.circl.lu/search", data={"search": text})
        r = res.text.split(">")
        cve_id = []
        cve_summary = []
        for c in r:
            if ("title=" in c):
                cve_summary.append(c.split("title=")[1])

            if ("</a" in c):
                c = c.split("</a")[0]
                if ("CVE-" in c):
                    cve_id.append(c)

        for i in range(0, len(cve_id)):
            # print(cve_id[i] + "==> " + cve_summary[i])
            if (key in cve_summary[i]):
             print(cve_id[i]+ " => " + cve_summary[i])

    def filter(self,id,key):
        dv = self.get_device(id)
        self.device_type = dv["device_type"]
        self.firmware = dv["device_firmware"]
        if(self.device_type !="NOt Known"):
         print("======== {} ======".format(self.device_type))
         self.cve_fl(self.device_type,key)
        if(self.firmware != "UNKNOWN"):
         print("======== {} ======".format(self.firmware))
         self.cve_fl(self.firmware,key)
    def exploits(self,id):
     self.cve_search(id)
     for i in range(0,len(self.cve_id)):
        pyxploitdb.searchCVE(self.cve_id[i])

    def exploits2(self, id):
        dv = self.get_device(id)
        self.device_type = dv["device_type"]
        self.firmware = dv["device_firmware"]
        pyxploitdb.searchEDB(self.firmware, _print=True, nb_results=30)
    def nmap(self,id):
        import os
        import subprocess
        dv = self.get_device(id)
        self.device_ip = dv["device_ip"]

        if platform.system() == "Linux":
            cmd = ["nmap", "-Pn", "-sU", "--script", "upnp-info", "-p", "1900", self.device_ip]
        else:
            os.chdir("C:/Program Files (x86)/Nmap/")
            cmd = ["nmap.exe", "-Pn", "-sU", "--script", "upnp-info", "-p", "1900", self.device_ip]

        run = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        res, err = run.communicate()
        if ("Server" in res):
         server = str(res).split("Server:")[1].split("Location:")[0].strip().split("|_")[0]
         location = str(res).split("Location: ")[1].split("  ")[0].strip()
         print("-------------------------------------------------------")
         if(server and location):
          print("Server : {}Location : {}".format(server,location))
        else:
            print("Nothing found")
    def show_usb(self):
        import subprocess
        cmd=["ls","/dev/","|","grep","-i","USB"]
        cmd2= ["ls", "/dev/", "|", "grep", "-i", "ttyS"]
        res1 = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        res2 = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        rest, errt = res1.communicate()
        resy, erry = res2.communicate()
        print("serial devices ")
        print(rest)
        print("USB-to-serial converters")
        print(resy)
    def uart(self,uu):
        print("CONNECT TX->RX RX->TX GND->GND")
        print("PLUG YOUR DEVICE")
        time.sleep(2)
        cmd = "screen {} {}".format(str(uu).split(":")[0],str(uu).split(":")[1])
        os.system(cmd)
    def mqtt(self,id):
        import os
        import subprocess
        dv = self.get_device(id)
        self.device_ip = dv["device_ip"]

        if platform.system() == "Linux":
            cmd = ["nmap", "-Pn", "-sV", "-p", "1883", self.device_ip]
        else:
            os.chdir("C:/Program Files (x86)/Nmap/")
            cmd = ["nmap.exe", "-Pn", "-sV",  "-p", "1883", "--script","mqtt-subscribe",self.device_ip]

        run = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        res, err = run.communicate()
        if("mosquitto" in res):
            print("----------------------------------------------------")
            rs = str(res).split("version")[1]
            print("mosquitto:"+rs)
            print("Receiving messages from all topics ")
            os.system("mosquitto_sub -t '#' -h {} -v".format(self.device_ip))
    def req(self,url,path):
        resp = requests.get(url+path)
        return resp.status_code
    def fuzzing(self,url,id):
        dv = self.get_device(id)
        self.device_ip = dv["device_ip"]
        psswd = ["/../etc/passwd","/../../etc/passwd","/../../../etc/passwd","../etc/passwd","../../etc/passwd","../../../etc/passwd","../../../../etc/passwd","/../../../../etc/passwd","/../../../../../etc/passwd","file:///etc/passwd"]
        self.url="http://"+self.device_ip
        self.fl="wd/wordlist.txt"
        self.ll_th=[]
        for pas in psswd:
           try:
            code= self.req(self.url,pas).status_code
            txt = self.req(self.url,pas).text
            if(code == 200 and "root" in txt):
               print ("[+] {}".format(pas))
           except:
               print("[-] {}".format(pas))
        cve= {"CVE-2023-2392":"scgi-bin/platform.cgi?page=time_zone.htm",1:"/admin",2:"/robots.txt",3:"/login"}
        if(os.path.isfile(self.fl) != True):
           os.system("curl -o wd/wordlist.txt https://raw.githubusercontent.com/bhavesh-pardhi/Wordlist-Hub/main/WordLists/api.txt")
        fp = open(self.fl, "r")
        count = len(fp.readlines())
        fp.close()
        fp = open(self.fl, "r")
        for d in range(0,count):
           self.th(fp.readline())
        fp.close()

    def th(self,lg):
      try:
        rt = requests.get(self.url+lg)
        if(rt.status_code == 200):
            print("[+]"+lg)
      except:
          print("[-]" + lg)
    def check_id(self,id):
        if(len(id) != 6):
            print("Id not correct ")
            exit(1)








