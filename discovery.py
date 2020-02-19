#!/usr/bin/env python

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) ifm electronic gmbh
#
# THE PROGRAM IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
#


# This is a sample code to provide an example how the ifm
# IPv4 discovery is implemented. This is code is reduced
# to its bare minimum and does not contain the needed error
# checks one would expect in production environments.
#
# To sniff the traffic between host and device you can use the following tcpdump commandline:
# sudo tcpdump -nnvXSs 0  -i < your interface for example eth0> udp port 3321

# Import of needed python modules
# %%
import socket
import threading
from socketserver import UDPServer, BaseRequestHandler
import struct
import argparse
import sys
import os

import platform
if(platform.system() == 'Linux'):
    try:
        if (os.getuid() != 0):
            print(sys.stderr, "Check your privileges. Root permissions are required, as shown in the following example:")
            print(sys.stderr, "sudo python discovery.py -i eth0 -a 192.168.0.69\n")
            sys.exit(1)
    except AttributeError as e:
        if(e != "module 'os' has no attribute 'getuid'"):
            assert(e)

# The magic byte for messages from the host to the device
broadcast = bytearray([0x10, 0x20, 0xef, 0xcf, 0x0c, 0xf9, 0x00, 0x00])
# The magic sent from the device as a response to a request
responsemagic = 0x19111981

# The port number for communication. It is recommended to use
# the same port for incoming and outgoing communication this
# help to pierce a hole through a firewall like the default firewall
# under Windows 7. This technique is called
# UDP hole punching (https://en.wikipedia.org/wiki/UDP_hole_punching)
PORT = 3321

class ifmIPv4Discovery():
    def __init__(self, ip='192.168.0.10'):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        self.s.bind((ip,PORT))
        self.s.settimeout(10)
        
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.disconnect()

    def connect(self, ip='192.168.0.10'):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        self.s.bind((ip,PORT))
        self.s.settimeout(10)

    def discover(self): 
        print(self.s.sendto(broadcast, ("<broadcast>", PORT) ))
        response, server = self.s.recvfrom(8)
        response, server = self.s.recvfrom(360)
        return self.checkResponseMagic(response)

    def checkResponseMagic(self, response):
        if responsemagic ==  struct.unpack('>I',response[0:4])[0]:
            device_ip = socket.inet_ntoa(response[4:8])
            gateway_ip = socket.inet_ntoa(response[8:12])
            subnetmask = socket.inet_ntoa(response[12:16])
            port = struct.unpack('>H',response[16:18])[0]
            vendor_id = struct.unpack('>H',response[18:20])[0]
            device_id = struct.unpack('>H',response[20:22])[0]
            mac=response[32:38]
            device_mac = response[32:38]
            device_flags = struct.unpack('>H',response[38:40])[0]
            device_hostname = response[40:104]
            device_devicename = response[104:]

            info = {
                'device_ip':device_ip,
                'gateway_ip':gateway_ip,
                'subnetmask':subnetmask,
                'port':port,
                'vendor_id':vendor_id,
                'device_id':device_id,
                'mac':mac,
                'device_mac':device_mac,
                'device_flags':device_flags,
                'device_hostname':device_hostname,
                'device_devicename':device_devicename
            }

            return info
            

    def change_ip(self,ip,mac):
        """Helper function to change the IP address"""
        print('Change IP of the device to: {} with mac: {}'.format(ip,":".join("{:02x}".format(ord(c)) for c in mac)))
        set_ip = bytearray([0]*20) # create a zero byte buffer
        set_ip[0:4] = [0x10,0x20,0xef,0xce] # inject the magic bytes
        set_ip[4:6] = struct.pack('>H',PORT)
        # set_ip[6:8] > those bytes are reserved and recommended to be filled with 0
        set_ip[8:12] = socket.inet_aton(ip) # convert the IP to 4 byte representation
        # set_ip[12:14] > those bytes are reserved and recommended to be filled with 0
        set_ip[14:] = mac # reuse the MAC address
        self.s.sendto(set_ip, ("<broadcast>", PORT)) # Send the configuration to the device
        # Due to the fact we are using UDP it is recommended to check if the IP change
        # was successful. The easiest way might be to use the broadcast again

    def disconnect(self):
        self.s.close()

# %%
if __name__ == '__main__': 

    info = []

    with ifmIPv4Discovery() as dis:
        info = dis.discover()
    
    print(info)

# %%
