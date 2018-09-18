import argparse
import binascii
from enum import Enum, IntEnum
#from pcapfile.protocols.linklayer import ethernet
#from pcapfile.protocols.network import ip
#from pcapfile import savefile
#import RPi.GPIO as GPIO
import pyshark

import time
import timeit

class L3(Enum):
    IP4 = 'IPv4',
    IP6 = 'IPv6'

class LED(IntEnum):
    red = 23,
    white = 24,
    blue = 18

protonums = {1: "ICMP",
             6: "TCP",
             17: "UDP",
             58: "IPv6-ICMP"}


def GPIO_setup():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(LED.red, GPIO.OUT, initial = 0)


def ip4addr(octets):
    return ".".join(str(i) for i in  octets)


def parse_ip_info(packet):
    ip_layer = packet.layers[1]
    if not hasattr(ip_layer, "version"):
        print("not an IP packet")
        return None

    ip_version = ip_layer.version
    print(ip_layer.field_names)
    src_addr = ip_layer.src
    dst_addr = ip_layer.dst
    protocol = None if not hasattr(ip_layer, "proto_type") else ip_layer.proto_type
    if ip_version == "4":
        protocol = ip_layer.proto
    elif ip_version == "6":
        protocol = ip_layer.nxt

    return {"src_addr": src_addr,
            "dst_addr": dst_addr,
            "protocol": protonums.get(int(protocol), protocol)}


def blink_eyes(packet_stats, rate):
    print("rate {}, {} packets".format(rate, len(packet_stats)))
    max_v = 3.3
    pps = len(packet_stats) / rate
    min_pps = 1.0
    print("packets per second: {}".format(pps))
    #GPIO.output(LED.red.value, pps >= min_pps)

def count(it):
    val = 0
    for i in it:
        val += 1
    return val


def blink_tcp_lights(packet_stats, rate):
    tcp = count(p for p in packet_stats if p and p["protocol"] == "TCP")
    pps = tcp / rate
    min_pps = 0.6
    print("packets per second: {}".format(pps))
    #GPIO.output(LED.red.value, pps >= min_pps)


def blink_lights(packet_stats, rate):
    blink_eyes(packet_stats, rate)
    blink_tcp_lights(packet_stats, rate)




def replay_packets(packets, segment_size=2, loop=False):
    last_timestamp = None
    last_ref_timestamp = packets[0].sniff_time if packets else None
    packet_stats = []
    for p in packets:
        print("")
        last_timestamp = p.sniff_time

        packet_info = parse_ip_info(p)
        print(packet_info)
        packet_stats.append(packet_info)

        if (last_timestamp - last_ref_timestamp).total_seconds() > segment_size:
            last_ref_timestamp = last_timestamp
            blink_lights(packet_stats, segment_size)
            packet_stats = []




def replay_pcap(filename):
    cap = pyshark.FileCapture(filename)
    print(cap[0])
    replay_packets(cap)
    cap.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="file name of pcap file", required=True)

    args = parser.parse_args()
    #GPIO_setup()

    replay_pcap(args.file)
