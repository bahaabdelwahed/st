# ST Smart Things
ST Smart Things Sentinel is an advanced security tool engineered specifically to scrutinize and detect threats within the intricate protocols utilized by IoT (Internet of Things) devices. In the ever-expanding landscape of connected devices, ST Smart Things Sentinel emerges as a vigilant guardian, specializing in protocol-level threat detection. This tool empowers users to proactively identify and neutralize potential security risks, ensuring the integrity and security of IoT ecosystems.

![0](https://github.com/bahaabdelwahed/st/assets/19738278/d525c53e-8cb4-4f92-9cb1-f05224060e67)

~ Hilali Abdel 


USAGE

python st_tool.py [-h] [-s] [--add ADD] [--scan SCAN] [--id ID] [--search SEARCH]
                 [--bug BUG] [--firmware FIRMWARE] [--type TYPE]
                 [--detect] [--tty] [--uart UART] [--fz FZ]


[Add new Device]

python3 smartthings.py -a 192.168.1.1

python3 smarthings.py -s --type TPLINK

python3 smartthings.py -s --firmware  TP-Link Archer C7v2

Search for CVE and Poc [ firmware and device type]
[![asciicast](https://asciinema.org/a/644172.svg)](https://asciinema.org/a/644172)

Scan device for open upnp ports 

python3 smartthings.py -s --scan upnp --id <device_id> 

get data from mqtt 'subscribe'

python3 smartthings.py -s --scan mqtt --id <device_id> 
