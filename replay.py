import argparse
import binascii
from enum import Enum, IntEnum
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile import savefile
import RPi.GPIO as GPIO

import time
import timeit

class L3(Enum):
    IP4 = 'IPv4',
    IP6 = 'IPv6'

class LED(IntEnum):
    red = 16,
    white = 12,
    blue = 18

ethertypes = {2048: L3.IP4, # 0x0800
              34525: L3.IP6 # 0x86DD
             }


protonums = {1: "ICMP",
             6: "TCP",
             17: "UDP"} 

self_ip4 = "10.2.0.133"

def GPIO_setup():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(LED.red, GPIO.OUT, initial = 0)
    GPIO.setup(LED.white, GPIO.OUT, initial = 0)


def ip4addr(octets):
    return ".".join(str(i) for i in  octets)


def parse_ip4_header(header_hex):
    header = binascii.unhexlify(header_hex)
    src_addr = ip4addr(header[12:16])
    dst_addr = ip4addr(header[16:20])
    
    protonum = header[9]
    return {"src_addr": src_addr, 
            "dst_addr": dst_addr,
            "incoming": dst_addr == self_ip4,
            "outgoing": src_addr == self_ip4,
            "protocol": protonums.get(protonum, "OTHER - {}".format(protonum))}



def count(it):
    val = 0
    for i in it:
        val += 1
    return val

def blink_proto_lights(protoname, packet_stats, rate, led, min_rate):
    proto = count(p for p in packet_stats if p["protocol"] == protoname)
    pps = proto / rate
    print("{} packets per second: {} %".format(protoname, 100.0 * pps))
    GPIO.output(led.value, pps > min_rate)




def blink_lights(packet_stats, rate):
    blink_proto_lights("TCP", packet_stats, rate, LED.white, min_rate=0.5)
    blink_proto_lights("UDP", packet_stats, rate, LED.red, min_rate=0.0)




def replay_packets(packets, rate, loop=False):
    for i in range(len(packets) // rate):
        print("")
        print("Packets {} through {}".format(i*rate, (i+1)*rate))
        packet_stats = []
        for p in packets[i*rate:(i+1)*rate]:

            frame = ethernet.Ethernet(p.raw())
            ethertype = ethertypes.get(frame.type)
            if ethertype is None:
                pass
            elif ethertype == L3.IP4:
                packet_info = parse_ip4_header(frame.payload)
                print(packet_info)
                packet_stats.append(packet_info)
            else:
                print(ethertype)
                print(frame.payload)
        blink_lights(packet_stats, rate)
        time.sleep(1)
            
            #print(ip.IP(binascii.unhexlify(frame.payload)).header)




def replay_pcap(filename, rate):
    with open(filename, "rb") as pfile:
        pcap = savefile.load_savefile(pfile, verbose=True)
        replay_packets(pcap.packets, rate)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="file name of pcap file", required=True)
    parser.add_argument("-r", "--rate", type=int, help="packets per second", default=1)
    args = parser.parse_args()
    GPIO_setup()

    while True:
        replay_pcap(args.file, args.rate)

    """
    replay = pcap.open_offline(name=None, promisc=True, immediate=True, timeout_ms=50)
    addr = lambda pkt, offset: '.'.join(str(pkt[i]) for i in range(offset, offset + 4))
    print(dir(sniffer))
    for ts, pkt in sniffer:
            protoversion = int(pkt[sniffer.dloff]) // 16 
            if protoversion == 4:
                header_words = pkt[sniffer.dloff] - (16 * protoversion)
                header_octets = 4*header_words
                header = pkt[sniffer.dloff:sniffer.dloff+header_octets]
                header_info = parse_ip4_header(header)
                if header_info["src_addr"] not in filtered_src and header_info["dst_addr"] not in filtered_dst:
                    print(header_info)
            else:
                print("IP protocol version {}".format(protoversion))
    """
