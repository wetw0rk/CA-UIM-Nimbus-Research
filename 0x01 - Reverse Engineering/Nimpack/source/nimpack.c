/*

Program name  : nimpack
Version       : 1.1
Author        : wetw0rk
GCC Version   : 8.3.0 (Debian 8.3.0-19)
Designed OS   : Linux

Description :
  Sends a probe based on how you decide to contruct it, this
  code is very hackish so as always no warranty ;). Majority
  of the "generation" occurs in packetgen.h.

*/

#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "packgen.h"

#define MAX_ARGUMENTS 20

void help()
{
  printf("usage: ./nimpack [-h] [-t TARGET] [-p PORT] [ARG=VAL]\n\n");
  printf("Nimpack - Nimbus packet generator\n\n");
  printf("optional arguments:\n");
  printf("  -h, --help                  show this help message and exit\n");
  printf("  -t TARGET, --target TARGET  target host to probe\n");
  printf("  -p PORT, --port PORT        nimcontroller port\n\n");
  printf("positional arguments:\n");
  printf("  probe\n");
  printf("  arg=val\n\n");
  printf("examples:\n");
  printf("  ./nimpack -t 192.168.88.130 -p 48000 directory_list directory=C:\\\\\n");
  printf("  ./nimpack -t 192.168.88.130 -p 48000 os_info\n");
  exit(0);
}

int main(int argc, char **argv)
{
  int c;
  int sock;
  int count;
  char *rhost, *rport;
  char *params[MAX_ARGUMENTS];
  char response[BUFSIZ];

  NimsoftProbe *probe;
  struct sockaddr_in srv;

  while (1)
  {
    static struct option long_options[] =
    {
      {"help",    no_argument,        0, 'h'},
      {"target",  required_argument,  0, 't'},
      {"port",    required_argument,  0, 'p'},
      {0, 0, 0}
    };

    int option_index = 0;

    c = getopt_long (argc, argv, "ht:p:", long_options, &option_index);

    if (c == -1)
      break;

    switch(c)
    {
      case 't':
        rhost = optarg;
        break;
      case 'p':
        rport = optarg;
        break;
      case 'h':
      default:
        help();
        break;
    }
  }

  if (argc < 6)
    help();

  if (optind < argc)
    while (optind < argc)
      params[count++] = argv[optind++];

  probe = packet_gen(params, count);

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("[-] Failed to create socket\n");
    return -1;
  }

  srv.sin_addr.s_addr = inet_addr(rhost);
  srv.sin_port = htons(atoi(rport));
  srv.sin_family = AF_INET;

  if (connect(sock , (struct sockaddr *)&srv, sizeof(srv)) < 0) {
    printf("[-] Connection Failed\n");
    return -1;
  }

  printf("[*] Sending generated probe (%d): ", probe->length);
  repr(probe->packet, probe->length);
  putchar('\n');

  send(sock, probe->packet, probe->length, 0);

  count = read(sock, response, BUFSIZ);

  printf("[+] Recieved: ");
  repr(response, count);

  free(probe);

  return 0;
}
