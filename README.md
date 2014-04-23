# TLS Heartbeat vulnerability scanner
A simple tool for scanning several hosts for the heartbeat vulnerability at once. The program will take a string of ips, hostnames or networks in CIDR notation. An example command is:
```
./hb-scan.py 192.168.1.1
```
The help message is as follows.
```
./hb-scan.py --help
usage: sage: hb-scan.py [-h] [-o OUTPUT] [-p PORT] [--timeout TIMEOUT] [-v]
                  ([-f FILE] | [ip [ip ...]] )

Basic scanner for the Heartbeat vulnerability

positional arguments:
  ip

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        File to write vulnerable hosts to.
  -p PORT, --port PORT  TCP port the scan. default=443
  --timeout TIMEOUT     Set timeout in seconds. default=1
  -v                    Prints verbose output
  -f FILE, --file FILE  File with hosts to scan
```