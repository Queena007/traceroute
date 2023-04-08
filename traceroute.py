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
# In this function  make the checksum of our packet
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
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of 
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    myChecksum = 0
    myID = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
    # Append checksum to the header.
    myChecksum = checksum(header + data)
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
        #Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = htons(myChecksum)
    # Don’t send the packet yet , just return the final packet in this function.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    #Fill in end

    # So the function ending should look like this

    packet = header + data
    return packet


def get_route(hostname):
    df = pd.DataFrame(columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
    destAddr = gethostbyname(hostname)
   
    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            timeLeft = TIMEOUT * (tries + 1)  # Increase timeLeft with each try
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            def get_route(hostname):
    
    mySocket.settimeout(TIMEOUT)
    timeout_occurred = False
    try:
        d = build_packet()
        mySocket.sendto(d, (hostname, 0))
        t = time.time()
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if not whatReady[0]:  # No response received
            timeout_occurred = True
    except Exception as e:
        print(e)  
        continue

    if timeout_occurred:
        print("*    *    * Request timed out.")
        df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': "", 'Hostname': "", 'Response Code': "Request timed out"}, ignore_index=True)
        continue


            except Exception as e:
                print(e)  
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

