#!/usr/bin/env python3
#
# Program name    : nimfuzz
# Version         : 1.2
# Author          : wetw0rk
# Python Version  : 3.4
# Designed OS     : Windows 10
#
# Description:
#   "Dumb" fuzzer that will loop through known Nimsoft / Nimbus probe commands
#   and send numerous bytes of a static BUFFER_LENGTH. You can also implement
#   a for loop to slowly increment lengths. This was designed to be ran from the
#   target OS. All crashes and errors will be written to log.txt.
#

import os
import sys
import time
import socket


TARGET            = "52.117.201.212"
PORT              = 48000
TIMEOUT           = 4
BUFFER_LENGTH     = 45000
NIMSOFT_DIECTORY  = "C:\\Program Files (x86)\\Nimsoft\\bin"

def main():

  fuzz_probes = [
    #------------- PROBE -----------#--------------------------------------------------------- ARGUMENTS ---------------------------------------------------#---- PERM ----#
    {"_status"                      : ["detail=1"]},                                                                                                        # 0
    {"_command"                     : ["detail=1"]},                                                                                                        # 0
    {"checkin"                      : ["hubaddr=/none/wetw0rk/wetw0rk","hubip=52.117.201.212"]},                                                            # 0
    {"probe_checkin"                : ["type=1"]},                                                                                                          # 0
    {"iptoname"                     : ["ip=52.117.201.212","port=48000"]},                                                                                  # 0
    {"nametoip"                     : ["name=controller"]},                                                                                                 # 0
    {"login"                        : ["type=1"]},                                                                                                          # 0
    {"probe_set_port"               : ["name=spooler","port=48001","pid=2652"]},                                                                            # 0
    {"port_register"                : ["name=wetw0rk","port=6555","pid=5205"]},                                                                             # 0
    {"port_unregister"              : ["name=wetw0rk","pid=5205"]},                                                                                         # 0
    {"port_reserve"                 : ["name=wetw0rk"]},                                                                                                    # 0
    {"port_reserve_starting_from"   : ["name=wetw0rk","start_port=6555"]},                                                                                  # 0
    {"get_info"                     : ["interfaces=1", "robot=wetw0rk"]},                                                                                   # 0
    {"remote_config_get"            : ["name=controller"]},                                                                                                 # 0
    {"remote_config_set"            : ["name=vs2017_vcredist_x86","section=win32","key=name","value=1","lockid=1"]},                                        # 0
    {"validate_license"             : ["license=C:\\test.txt", "mode=1"]},                                                                                  # 0
    {"test_alarm"                   : ["level=3"]},                                                                                                         # 0
    {"remote_list"                  : ["detail=1"]},                                                                                                        # 0
    {"_shutdown"                    : ["id=1"]},                                                                                                            # 0
    {"_nis_cache"                   : ["age=1","bulk_size=50","robot=wetw0rk"]},                                                                            # 0
    {"_nis_cache_advanced"          : ["age=1","bulk_size=50","robot=wetw0rk","min_age=0"]},                                                                # 0
    {"_nis_cache_clean"             : ["robot=wetw0rk","min_age=2"]},                                                                                       # 0
    {"_reset_device_id_and_restart" : ["robot=wetw0rk"]},                                                                                                   # 0
    {"hubcall_robotup"              : ["license=1","hubdomain=none","hubname= ","hubrobotname= ","hubpost_port=48002","origin,ssl_cipher=0","ssl_mode=2"]}, # 0
    {"hubcall_update_hub_info"      : ["origin=test"]},                                                                                                     # 0
    {"validate_ip_suggestions"      : ["input_ips=50"]},                                                                                                    # 0
    {"_debug"                       : ["level=1","trunc_size=50","trunc_time=15","now=14"]},                                                                # 1
    {"probe_list"                   : ["name=hdb","robot=wetw0rk"]},                                                                                        # 1
    {"probe_config_get"             : ["name=hdb","robot=wetw0rk","var=group"]},                                                                            # 1
    {"probe_tail_logfile"           : ["name=hdb","size=50","prev_record=1"]},                                                                              # 1
    {"probe_tail_logfile_session"   : ["name=hdb","max_buffer=50","from_start=1"]},                                                                         # 1
    {"inst_list"                    : ["package=vs2008sp1_redist_x64"]},                                                                                    # 1
    {"directory_list"               : ["directory=C:\\","type= ","detail=1"]},                                                                              # 1
    {"file_stat"                    : ["directory=C:\\","file=test.txt"]},                                                                                  # 1
    {"text_file_get"                : ["directory=C:\\","file=test.txt","buffer_size=50"]},                                                                 # 1
    {"file_get_start"               : ["directory=C:\\","file=test.txt","type=0","buffer_size=50","start_pos=1"]},                                          # 1
    {"file_get_next"                : ["id=1"]},                                                                                                            # 1
    {"file_get_end"                 : ["id=1"]},                                                                                                            # 1
    {"get_environment"              : ["variable=PATH"]},                                                                                                   # 1
    {"run_controller_plugins_now"   : ["plugin_name=test"]},                                                                                                # 1
    {"plugins_get_info"             : ["plugin_name=test"]},                                                                                                # 1
    {"verify_file"                  : ["owner= ","path=C:\\"]},                                                                                             # 1
    {"verify_files"                 : ["owner= "]},                                                                                                         # 1
    {"probe_set_priority_level"     : ["name=hdb","priority_level=1"]},                                                                                     # 2
    {"maint_until"                  : ["until=2","for=2","comment=hello","from=1"]},                                                                        # 2
    {"probe_register"               : ["name=test","active=1","type=script","timespec=test","command=cmd","arguments=help","workdir=C:\\","config=c.cfg",   # 3
                                       "datafile=test.txt","logfile=log.txt","description=fuckit","group,fail_window=0","realip=127.0.0.1"]},               # 3
    {"probe_unregister"             : ["name=test","noforce=1"]},                                                                                           # 3
    {"probe_activate"               : ["name=test"]},                                                                                                       # 3
    {"probe_deactivate"             : ["name=test","noforce=1","waitforstop=1"]},                                                                           # 3
    {"probe_store"                  : ["filename=test.txt"]},                                                                                               # 3
    {"probe_config_lock"            : ["name=test","locktype=1","lockid=test","robot=wetw0rk"]},                                                            # 3
    {"probe_config_lock_list"       : ["name=test"]},                                                                                                       # 3
    {"probe_config_set"             : ["name=test","section=test","key=test","value=test","lockid=1","robot=wetw0rk"]},                                     # 3
    {"probe_start"                  : ["name=test"]},                                                                                                       # 3
    {"probe_stop"                   : ["name=test"]},                                                                                                       # 3
    {"probe_change_par"             : ["name=test","par=test","value=test"]},                                                                               # 3
    {"probe_verify"                 : ["name=test"]},                                                                                                       # 3
    {"restart_all_probes"           : ["marketplace_only=1"]},                                                                                              # 3
    {"sethub"                       : ["hubdomain=none","hubname= ","hubip=52.117.201.212","hub_dns_name= ","hubport=48002","robotip_alias=wtew0rk"]},      # 3
    {"log_level"                    : ["level=1"]},                                                                                                         # 3
    {"inst_pkg"                     : ["package=test"]},                                                                                                    # 3
    {"inst_file_start"              : ["package=test","file=test.txt","type=script","mode=rwx","crc= "]},                                                   # 3
    {"inst_file_next"               : ["id=1"]},                                                                                                            # 3
    {"inst_file_end" 	            : ["id=1"]},                                                                                                            # 3
    {"inst_execute"                 : ["package=test","section=3","expire=1","robot_name=wetw0rk"]},                                                        # 3
    {"inst_pkg_remove"              : ["package=test","probe=test","noforce=1"]},                                                                           # 3
    {"inst_request"                 : ["package=test","distsrv=test"]},                                                                                     # 3
    {"text_file_put"                : ["directory=C:\\","file=test.txt","mode=rwx","file_contents=hello_world"]},                                           # 3
    {"file_put_start"               : ["directory=C:\\","file=test.txt","type=script","mode=rwx"]},                                                         # 3
    {"file_put_next"                : ["id=1"]},                                                                                                            # 3
    {"file_put_end"                 : ["id=1"]},                                                                                                            # 3
    {"check_product_guid"           : ["guid=1"]},                                                                                                          # 3
    {"_audit_send"                  : ["description=test","status=1"]},                                                                                     # 3
    {"check_marketplace_user"       : ["encrypted_username=test","encrypted_password=pass"]},                                                               # 3
    {"protect_file"                 : ["owner= ","path=C:\\"]},                                                                                             # 3
    {"unprotect_file"               : ["owner= ","path=C:\\"]},                                                                                             # 3
    {"_audit_type"                  : ["type=1"]},                                                                                                          # 4
    {"_audit_restore"               : ["probe=test","checkpoint=1","lockid=12","robot=wetw0rk"]},                                                           # 4
  ]

  tested = ["directory",  # RCE
            "name",       # MSVCR90!write_char+0x24
            "robot",      # MSVCR90!write_char+0x24
            "probe",      # MSVCR90!write_char+0x24
            "hubdomain",  # MSVCR90!write_char+0x24
            "hubname",    # MSVCR90!write_char+0x24
            "package",    # MSVCR90!write_char+0x24
            ]

  fuzzer(
    fuzz_probes,    # list of commands to fuzz along with args
    BUFFER_LENGTH,  # fuzz length (static but can be looped)
    tested          # avoid fuzzing these arguments
  )

# crash_handler: does what you would expect, made its own function in case
# I start getting spammed
def crash_handler(probe_info):

  note = f"Probe: {probe_info[0]}\nArgument: {probe_info[1]}\nEvil Packet: {repr(probe_info[2])}\n\n"

  check = check_controller_state("", "", "")
  if check != 1:
    logger(note)

  if os.getcwd() == NIMSOFT_DIECTORY:
    print(f"{BOLD}{YELLOW}      Crash state:{END} Restarting Nimbus Controller")
    os.system("nimbus -stop")
    time.sleep(3)
    os.system("nimbus -start")

  return

# logger: write all crash cases into the log.txt file
def logger(note):

  if os.path.isfile("logs.txt"):
    fd = open("logs.txt", "a+")
  else:
    fd = open("logs.txt", 'w+')

  fd.write(note)
  fd.close()

# fuzzer (
#   [ { probe name: [ arg=argv, arg=argv] } ]
#   sizeOf(FuzzPayload)
#   [ProbeArgvsToIgnore]
# )
#
# fuzzer: generates and sends fuzzed arguments majority of program flow
# occurs here
def fuzzer(fuzz_probes, flen, tested_args):

  fuzz_cases = generate_cases()

  for i in range(len(fuzz_probes)):

    command = fuzz_probes[i]

    for probe_name, arguments in command.items():

      print(f"{BOLD}{PURPLE}    Test Step: Fuzzing Node:{END} {probe_name}")
      for i in range(len(arguments)):
        test_case = arguments[i]
        tmp_args = []

        for j in range(len(fuzz_cases)):
          for k in range(1):
            final_args = []

            payload = fuzz_cases[j] * ((k+1) * (flen))

            backup = test_case # backup the original argument

            if (str(test_case.split('=')[0]) not in tested_args):
              test_case = test_case.replace(
                str(test_case.split('=')[1]),
                payload
              )

            for l in range(len(arguments)):
              if l == i and i == 0:
                tmp_args = [test_case]
              elif l == 0 and i != 0:
                tmp_args = [arguments[l]]
              elif l == i and l != 0:
                tmp_args += test_case,
              else:
                tmp_args += arguments[l],

            final_args = tmp_args

            packet = generate_probe(probe_name, final_args)

            print(f"\tInfo: Opening target connection ({TARGET}:{PORT})")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
              sock.settimeout(TIMEOUT)
              sock.connect((TARGET, PORT))

              print(f"\tConnection opened.")
              print(f"\tInfo: Sending {repr(fuzz_cases[j])} -> {len(payload)} bytes...")
              print(f"{BOLD}{PURPLE}      Test Step: Fuzzing Node:{END} '{str(test_case.split('=')[0])}'")

              sock.send(bytes(packet, 'utf-8'))

              r = sock.recv(4096)

              print(f"\t{BOLD}{CYAN}Transmitted {len(payload)} bytes (truncated buffer): {BOLD}{RED}{repr(packet[:500])}{END}")
              print(f"\t{BOLD}{CYAN}Received {len(r)} bytes:{END}{BOLD}{BLUE}{r}{END}")
              time.sleep(.5)
            except:
              check = check_controller_state(probe_name, str(test_case.split('=')[0]), packet)
              if (check != 1):
                crash_handler(check)

            test_case = backup # test completed restore argument

# check_controller_state: if we get a timeout or no response verify that the
# target host is responsive, if not we have a crash
def check_controller_state(probe, argv, packet):

  print(f"{BOLD}{RED}      Possible crash:{END} Checking controller state")
  print("\tWaiting 5 seconds")
  time.sleep(5)

  print(f"\tInfo: Opening target connection ({TARGET}:{PORT})")
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:

    sock.settimeout(TIMEOUT)
    sock.connect((TARGET, PORT))

    print("\tConnection opened.")

    sock.send(bytes(generate_probe("os_info", []), 'utf-8'))
    r = sock.recv(4096)

    print(f"\t{BOLD}{CYAN}Received {len(r)} bytes: {BOLD}{BLUE}{r}{END}")
    print(f"{BOLD}{RED}      Crash state:{END} False positive")

    return 1

  except:
    print(f"{BOLD}{RED}      Crash state:{END} Likely a crash")

  return [probe, argv, packet]

# generate_probe: returns a dynamically generated probe based on the nimpack
# C program I previously wrote.
def generate_probe(probe, args):

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
  packet_body   = (
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

  return probe

# generate_cases: returns a list object containing each fuzz case to later be
# duplicated / multiplied into a buffer.
def generate_cases():

  test_bytes = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00"
  )
  test_other = ["../", "..\\", "..%2f", "..%5c", "http://", "~"]

  cases = []
  for i in range(len(test_bytes)):
    cases += test_bytes[i],
  for i in range(len(test_other)):
    cases += test_other[i],

  return cases

RED     = '\033[31m'
BLUE    = '\033[94m'
BOLD    = '\033[1m'
YELLOW  = '\033[93m'
GREEN   = '\033[32m'
CYAN    = '\033[96m'
PURPLE  = '\033[95m'
END     = '\033[0m'

if __name__ == '__main__':
  try:
    if os.name == "nt":
      os.system("color")
    main()
  except KeyboardInterrupt:
    sys.exit(-1)
