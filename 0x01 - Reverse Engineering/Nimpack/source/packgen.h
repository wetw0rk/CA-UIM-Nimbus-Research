/*

Header name : packgen.h
Version     : 1.1
Author      : Milton Valencia (wetw0rk)
GCC Version : 8.3.0 (Debian 8.3.0-19)
Designed OS : Linux

Description :
  This will generate a probe based on args passed into the function
  not the cleanest method but it works. Please, forgive my horrible
  code wrote this in a jiffy.

Functions :
  void pparse(char *packet)
  void repr(char *buffer, int nbytes)
  NimsoftProbe *packet_gen(char *lparams[], int nparams)

*/

/* max amount of bytes in each section of the probe */
#define PHLEN 300   /* header      */
#define PBLEN 2000  /* body        */
#define PALEN 2000  /* argv        */
#define FPLEN 5000  /* final probe */

/* source address: can be anything */
#define CLIENT "127.0.0.1/1337"

#define INTSIZ(x) snprintf(NULL, 0, "%i", x)

unsigned char packet_header[] = \
"\x6e\x69\x6d\x62\x75\x73\x2f\x31\x2e\x30\x20%d\x20%d\x0d\x0a";
unsigned char packet_body[] = \
                                    /* nimbus header */
"\x6d\x74\x79\x70\x65\x0F"          /* mtype         */
"\x37\x0F\x34\x0F\x31\x30\x30\x0F"  /* 7.4.100       */
"\x63\x6d\x64\x0F"                  /* cmd           */
"\x37\x0F%d\x0F"                    /* 7.x           */
"%s\x0F"                            /* probe         */
"\x73\x65\x71\x0F"                  /* seq           */
"\x31\x0F\x32\x0F\x30\x0F"          /* 1.2.0         */
"\x74\x73\x0F"                      /* ts            */
"\x31\x0F%d\x0F"                    /* 1.X           */
"%d\x0F"                            /* UNIX EPOCH    */
"\x66\x72\x6d\x0F"                  /* frm           */
"\x37\x0F%d\x0F"                    /* 7.15          */
"%s\x0F"                            /* client addr   */
"\x74\x6f\x75\x74\x0F"              /* tout          */
"\x31\x0F\x34\x0F\x31\x38\x30\x0F"  /* 1.4.180       */
"\x61\x64\x64\x72\x0F"              /* addr          */
"\x37\x0F\x30\x0F";                 /* 7.0           */

typedef struct {
  char *packet;
  int length;
} NimsoftProbe;

/* packet_gen: generate a probe dynamically (some hardcoded bytes) */
NimsoftProbe *packet_gen(char *lparams[], int nparams)
{
  int c, i, j;              /* loops, chars, the norm   */
  int index = 0;            /* index for arguments      */
  int fmt_args;
  int lbody = 0, largs = 0; /* length of body / args  */

  char *tptr;               /* tmp pointer to args/vals */
  char pheader[PHLEN];      /* packet header            */
  char pbody[PBLEN];        /* packet body              */
  char pargs[PALEN];        /* packet arguments         */
  char pbuffer[FPLEN];      /* packet buffer            */


  char *probe = lparams[0]; /* probe name / module      */

  int epoch_time = (int)time(NULL);

  NimsoftProbe *probePtr = (NimsoftProbe*)malloc(sizeof(NimsoftProbe));

  /* get the length of the arguments to format before format */
  fmt_args = snprintf(NULL, 0, "%d%s%d%d%d%s",
    (strlen(probe)+1),
    probe,
    (INTSIZ(epoch_time)+1),
    epoch_time,
    (strlen(CLIENT)+1),
    CLIENT
  );

  /* if we cannot store all of the arguments properly exit */
  if ((fmt_args + sizeof(packet_body)) > PBLEN) {
    printf("Failed to generate packet body\n");
    exit(-1);
  }

  /* else format probe args + respective lengths */
  lbody = snprintf(pbody, PBLEN, packet_body,
    (strlen(probe)+1),
    probe,
    (INTSIZ(epoch_time)+1),
    epoch_time,
    (strlen(CLIENT)+1),
    CLIENT
  );

  /* begin formatting the probe arguments if any */
  for (i = 1; i < nparams; i++)
  {
    /* split up the any arguments and values */
    for (j = 0; j < strlen(lparams[i]); j++)
      if ((c = lparams[i][j]) == '=')
        lparams[i][j] = '\x00', index = ++j;

    tptr = lparams[i]; /* probe selected */

    if ((c = 1, c += strlen(tptr)) < PALEN) {
      largs += snprintf(pargs+largs, c, "%s", tptr);
      largs++;
    } else {
      printf("Failed to generate packet arguments\n");
      exit(-1);
    }

    if (index > 0) /* arguments if any */
    {
      tptr = tptr+index;

      if ((largs + strlen(tptr) + 2) < PALEN)
      {
        largs += snprintf(pargs+largs, 2, "%s", "1");
        largs++;

        largs += snprintf(pargs+largs, strlen(tptr)+1, "%d", strlen(tptr)+1);
        largs++;
      } else {
        printf("Failed to generate packet arguments\n");
        exit(-1);
      }

      c = 1, c += strlen(tptr);
      if ((largs + c) < PALEN)
      {
        largs += snprintf(pargs+largs, c, "%s", tptr);
        largs++;
      } else {
        printf("Failed to generate packet arguments\n");
        exit(-1);
      }
    }
  }

  /* program arguments have been generated form the final probe pbuff */
  index = snprintf(pbuffer, FPLEN, packet_header, lbody, largs);
  index += lbody;

  /* append the packet body to the header*/
  if (index < FPLEN) {
    strncat(pbuffer, pbody, lbody);
  } else {
    printf("Failed to concatenate packet body\n");
    exit(-1);
  }

  /* replace all occurences of 0x0f with a NULL byte */
  for (i = 0; i < index; i++)
    if (pbuffer[i] == '\x0f')
      pbuffer[i] = '\x00';

  /* append probe arguments */
  if ((index + largs) < FPLEN) {
    for (i = 0; i < largs; i++)
      pbuffer[index++] = pargs[i];
  }
  else {
    printf("Failed to concatenate packet arguments\n");
    exit(-1);
  }

  probePtr->packet = pbuffer;
  probePtr->length = index;

  return probePtr;
}

/* repr: print "raw" buffer similar to pythons repr() */
void repr(char *buffer, int nbytes)
{
  printf("'");
  for (int i = 0; i < nbytes; i++)
  {
    if (isprint(buffer[i]) && buffer[i] != '\\')
      printf("%c", buffer[i]);
    else if (buffer[i] == '\\')
      printf("\\\\");
    else if (buffer[i] == '\x0a')
      printf("\\n");
    else if (buffer[i] == '\x0d')
      printf("\\r");
    else
      printf("\\x%02x", buffer[i]);
  }
  printf("'\n");
}
