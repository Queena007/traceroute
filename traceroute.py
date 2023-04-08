from socket import *
import os
import sys
import struct
import time
import select
import binascii
import pandas as pd
from socket import herror

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 60
TIMEOUT = 2.0
TRIES = 1

# ... (checksum and build_packet functions remain the same)

def get_route(hostname):
    timeLeft = TIMEOUT
    df = pd.DataFrame(columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
    destAddr = gethostbyname(hostname)
   
    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
 
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if not whatReady[0]:  # Timeout
                    print("*    *    * Request timed out.")
                    df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': "", 'Hostname': "", 'Response Code': "Request timed out"}, ignore_index=True)
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': addr[0], 'Hostname': "", 'Response Code': "Request timed out"}, ignore_index=True)
            except Exception as e:
                print(e)  # uncomment to view exceptions
                continue

            else:
                icmpHeader = recvPacket[20:28]
                types, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

                try:
                    router_hostname = gethostbyaddr(addr[0])[0]
                except herror:
                    router_hostname = "hostname not returnable"

                if types == 11:
                    df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': addr[0], 'Hostname': router_hostname, 'Response Code': "TTL Exceeded"}, ignore_index=True)
                elif types == 3:
                    df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': addr[0], 'Hostname': router_hostname, 'Response Code': "Destination Unreachable"}, ignore_index=True)
                elif types == 0:
                    df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': addr[0], 'Hostname': router_hostname, 'Response Code': "Echo Reply"}, ignore_index=True)
                    return df
                else:
                    df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': addr[0], 'Hostname': router_hostname, 'Response Code': "Error"}, ignore_index=True)
                break
    print(df)
    return df

if __name__ == '__main__':
    get_route("google.co.il")
