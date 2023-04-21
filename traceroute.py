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

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

        if countTo < len(string):
            csum += (string[len(string) - 1])
            csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    myChecksum = 0
    myID = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    df = pd.DataFrame(columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
    destAddr = gethostbyname(hostname)
    print("Tracing route to", hostname, "(", destAddr, ")\n")
    consecutive_timeouts = 0

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            timeout_occurred = False
            try:
                d = build_packet()
                mySocket.sendto(d, (destAddr, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], TIMEOUT)
                howLongInSelect = (time.time() - startedSelect)
                if not whatReady[0]:
                    timeout_occurred = True
            except Exception as e:
                print(e)
                continue

            if timeout_occurred:
                print("*    *    * Request timed out.")
                df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': "", 'Hostname': "", 'Response Code': "Request timed out"}, ignore_index=True)
                consecutive_timeouts += 1
                if consecutive_timeouts >= 3:
                    break
                continue

            try:
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = TIMEOUT - howLongInSelect
                consecutive_timeouts = 0
            except timeout:
                df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': "", 'Hostname': "", 'Response Code': "Request timed out"}, ignore_index=True)
                consecutive_timeouts += 1
                if consecutive_timeouts >= 3:
                    break
                continue

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
            # Add an extra hop with a timed-out request
            df = df.append({'Hop Count': ttl + 1, 'Try': tries, 'IP': "", 'Hostname': "", 'Response Code': "Request timed out"}, ignore_index=True)
            print(df)
            return df

   

            else:
                df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': addr[0], 'Hostname': router_hostname, 'Response Code': "Error"}, ignore_index=True)
            break

        if consecutive_timeouts >= 3:
            break

    print(df)
    return df

if __name__ == '__main__':
    get_route("google.co.il")
