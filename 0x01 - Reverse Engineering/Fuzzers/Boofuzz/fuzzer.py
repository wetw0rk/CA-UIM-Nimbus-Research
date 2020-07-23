'''

This fuzzer was crafted before any reverse engineering

'''

from boofuzz import *

HOST = "192.168.245.150"
PORT = 48000

def result(sock):
  sock.recv(1024)

def main():
  session = sessions.Session(
    receive_data_after_fuzz = 1,
    session_filename = "nimsoft.session",
    sleep_time = 4,
    target = Target(
      SocketConnection(host=HOST, port=PORT, proto="tcp")
    )
  )

  s_initialize("probe_packets")

  s_static("nimbus/1.0 113 28\r\n")
  s_static("mtype\x00")
  s_string("7")
  s_static("\x004\x00100\x00")
  s_static("cmd\x00")
  s_string("7")
  s_static("\x009\x00")

  s_group("probes", values=[
    "os_info\x00",
    "get_info\x00",
    "probe_list\x00",
  ])

  if s_block("probe", group="probes"):
    s_string("seq")
    s_static("\x00")
    s_string("1")
    s_static("\x00")
    s_string("2")
    s_static("\x00")
    s_string("0")
    s_static("\x00")
    s_string("ts")
    s_static("\x00")
    s_string("1")
    s_static("\x00")
    s_string("11")
    s_static("\x00")
    s_string("1570203795")
    s_static("\x00")
    s_string("frm")
    s_static("\x00")
    s_string("7")
    s_static("\x00")
    s_string("22")
    s_static("\x00")
    s_string("192.168.245.150")
    s_string("/")
    s_string("50293")
    s_static("\x00")
    s_string("tout")
    s_static("\x00")
    s_string("1")
    s_static("\x00")
    s_string("4")
    s_static("\x00")
    s_string("180")
    s_static("\x00")
    s_string("addr")
    s_static("\x00")
    s_string("7")
    s_static("\x00")
    s_string("0")
    s_static("\x00")
    s_string("interfaces")
    s_static("\x00")
    s_string("1")
    s_static("\x00")
    s_string("2")
    s_static("\x00")
    s_string("0")
    s_static("\x00")
    s_string("robot")
    s_static("\x00")
    s_string("7")
    s_static("\x00")
    s_string("1")
    s_static("\x00\x00")
  s_block_end()

  session.connect(s_get("probe_packets"))
  session.fuzz()

if __name__ == "__main__":
  main()
