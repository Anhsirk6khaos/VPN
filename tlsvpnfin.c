/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include "aes.h"
#include "hmac.h"
#include "openssl_hostname_validation.h"

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

#define STDIN 0

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buffer2, int n){
  
  int nread;

  if((nread=read(fd, buffer2, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buffer2, int n){
  
  int nwrite;

  if((nwrite=write(fd, buffer2, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buffer2".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buffer2, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buffer2, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buffer2 += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *messages, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, messages);
	vfprintf(stderr, messages, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *messages, ...) {

  va_list argp;
  
  va_start(argp, messages);
  vfprintf(stderr, messages, argp);
  va_end(argp);
}

/* Print Hex format of the key and IV which will be exchanged once SSL/TLS connection between the server and the client is set*/
void Hex_format_printing(uint8_t *buffer2, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    printf("%02x ", buffer2[i]);
  }
  printf("\n");
}


/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/


void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
//  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  char receiver[100];

  progname = argv[0];
  
  /* A 256 bit key */
  unsigned char *key = (unsigned char*)malloc(32);

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char*)malloc(16);

  /* Lets setup all the Library needed for the working of SSL and Enc*/
  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();
  SSLeay_add_ssl_algorithms();
  OPENSSL_config(NULL);

  /* Initialization Variables*/
  SSL_CTX * sslctx;
  BIO *sbio, *bbio, *acpt, *out;
  SSL *ssl;
  char tmpbuf[11];
  char session_change[33];
  static int ssl_session_ctx_id = 1;
  X509 *server_cert;

  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /*******************************************************************************************
  *The below is SSL/TLS connection code which ensures that server and client authentication*
  *happens, the keys needed for encryption and HMAC are shared securely using a TCP connection*
  *Once key is exchanges, then we can move to ensure the confidentiality and integrity of VPN
  *********************************************************************************************/

  /* This is the SSL code with BIO. BIO checks at a more basic level*/

  /*Client-SSL*/

   if (cliserv == CLIENT) 
   {
    sslctx = SSL_CTX_new(SSLv23_client_method());
    if (!sslctx) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    if (SSL_CTX_use_certificate_file(sslctx, "/home/cs528user/client.crt", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(2);
    }
    if (SSL_CTX_use_PrivateKey_file(sslctx, "/home/cs528user/client.key", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(3);
    }
    if (SSL_CTX_check_private_key(sslctx) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(4);
    }
    if (SSL_CTX_load_verify_locations(sslctx, "/home/cs528user/ca.crt", NULL) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(5);
    }
    SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    sbio = BIO_new_ssl_connect(sslctx);

    BIO_get_ssl(sbio, &ssl);

    if (!ssl) {
      ERR_print_errors_fp(stderr);
      exit(6);
    }

    /* Don't want any retries */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* set connection parameters */
    BIO_set_conn_hostname(sbio, remote_ip);
    BIO_set_conn_port(sbio, "4433");

    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* Now that we have established the connection, Let's try to establish the server*/

    do_debug("This is an attempt to connect to the server from the client...\n");

    if (BIO_do_connect(sbio) <= 0) {
	fprintf(stderr, "Error connecting to server\n");
	ERR_print_errors_fp(stderr);
    BIO_free_all(sbio);
    BIO_free(out);
    SSL_CTX_free(sslctx);
    exit(1);
    }
    do_debug(" Success!!!!!.....We did it-Connection(Client)!!!!\n");

    /*Since It is a TCP connection, we need to establish Handshake. We are doing this becoz of the UDP, If .*/

    do_debug(" This is an attempt to establish SSL handshake to the server\n");
    if (BIO_do_handshake(sbio) <= 0) {
	fprintf(stderr, "Error establishing SSL Handshake\n");
	ERR_print_errors_fp(stderr);
    BIO_free_all(sbio);
    BIO_free(out);
    SSL_CTX_free(sslctx);
    exit(1);
    }
    do_debug(" Success!!!!!.....We did it-Handshake(Client)!!!!\n");


    // Recover the server's certificate
	server_cert =  SSL_get_peer_certificate(ssl);
	if (server_cert == NULL) {
		// The handshake was successful although the server did not provide a certificate
		// Most likely using an insecure anonymous cipher suite... get out!
		printf("Could not recover the server certificate for hostname verification\n");
	}

	// Validate the hostname
	if (validate_hostname("Nithya", server_cert) != MatchFound) {
		fprintf(stderr, "Hostname validation failed.\n");
	}



    /* We retrieve the master key from the session */
    SSL_SESSION *session = SSL_get_session(ssl);
    do_debug("MASTERKEY:\n");
    Hex_format_printing(session->master_key, session->master_key_length);
    do_debug("copying key:\n");
    memcpy(key, (session->master_key), 32);
    Hex_format_printing(key, 32);
    do_debug("copying iv:\n");
    memcpy(iv, &(session->master_key[32]), 16);
    Hex_format_printing(iv, 16);


   }

   /*Server SSL code*/
   /*This code ensures that server certificate is validated, the chain of certificate is also checked. since */

  else
  {
    sslctx = SSL_CTX_new(SSLv23_server_method());

    if (!sslctx) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    if (SSL_CTX_use_certificate_file(sslctx, "/home/cs528user/server.crt", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(2);
    }
    if (SSL_CTX_use_PrivateKey_file(sslctx, "/home/cs528user/server.key", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(3);
    }
    if (SSL_CTX_check_private_key(sslctx) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(4);
    }
    if (SSL_CTX_load_verify_locations(sslctx, "/home/cs528user/ca.crt", NULL) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(5);
    }
    SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* New SSL BIO setup as server */
    sbio = BIO_new_ssl(sslctx, 0);

    BIO_get_ssl(sbio, &ssl);

    if (!ssl) {
      ERR_print_errors_fp(stderr);
      exit(6);
    }

    /* Create the buffering BIO */
    bbio = BIO_new(BIO_f_buffer());

    /* Add to chain */
    sbio = BIO_push(bbio, sbio);

    acpt = BIO_new_accept("4433");
    BIO_set_accept_bios(acpt, sbio);

    do_debug("Setting up the accept BIO to see if the server will accept.....\n");
    if (BIO_do_accept(acpt) <= 0) {
      do_debug("Error setting up accept BIO\n");
      ERR_print_errors_fp(stderr);
      return (0);
    }
    do_debug("Success!!!!!.....We did it-BIO Connection initiated-(server)\n");

    /* Note -  I removed the repeating one if this code doesn't work we should add the above again......*/
    /* Added it now- see below*/

      /* Now wait for incoming connection */
    do_debug("Setting up the incoming connection for the BIO... \n");
    if (BIO_do_accept(acpt) <= 0) {
      do_debug("Error in connection\n");
      ERR_print_errors_fp(stderr);
      return (0);
    }
    do_debug("Success!!!!!.....We did it-BIO Connection established-(server)\n");

    /* We only want one connection so remove and free accept BIO */

    sbio = BIO_pop(acpt);

    BIO_free_all(acpt);

    do_debug("I am waiting for the SSL handshake...\n");
    if (BIO_do_handshake(sbio) <= 0) {
      do_debug("Error in SSL handshake\n");
      ERR_print_errors_fp(stderr);
      return (0);
    }
    do_debug("Success!!!!!.....We did it-BIO Handshake-(server)\n");
    srand((unsigned)time(NULL));
    BIO_flush(sbio);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    sleep(1);
    BIO_get_ssl(sbio, &ssl);
    SSL_SESSION *session = SSL_get_session(ssl);

    do_debug("MASTERKEY:\n");
    Hex_format_printing(session->master_key, session->master_key_length);
    do_debug("copying key:\n");
    memcpy(key, (session->master_key), 32);
    Hex_format_printing(key, 32);
    do_debug("copying iv:\n");
    memcpy(iv, &(session->master_key[32]), 16);
    Hex_format_printing(iv, 16);

  } 


  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

if (cliserv == CLIENT) 
   {
    /*************************************************************************************************
  *Now the SSL/TLS connection is establishes, It is time to send and receieve message more safely by 
  *using Encryption and Haashing
  **************************************************************************************************/

    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);
    char *intro = "Hello this is a UDP connection with SSL/TLS connection on top for key exchange";
    /* sendto request */
     int l = sendto(sock_fd,intro,strlen(intro),0,(struct sockaddr *)&remote,sizeof(remote));
     if( l < 0) perror("sendto");

    net_fd = sock_fd;
    do_debug("CLIENT (After SSL/TLS Connection): Connected to server %s\n", inet_ntoa(remote.sin_addr));
   }

else
{
/*************************************************************************************************
  *Now the SSL/TLS connection is establishes, It is time to send and receieve message more safely by 
  *using Encryption and Haashing
  **************************************************************************************************/
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    
    
    bzero(receiver, 100);
    int remoteAddrLen = sizeof(struct sockaddr_in);
    int len = recvfrom(sock_fd, receiver, 100, 0, (struct sockaddr *) &remote, &remoteAddrLen);
    if (len<0)
    {
      perror("recvfrom()");
      exit(1);
    }
    printf("Connected with client finally- This connection is once the client has SSL/TLS: %s\n", receiver);
    net_fd = sock_fd;

    do_debug("SERVER(After SSL/TLS Connection): Client connected from %s\n", inet_ntoa(remote.sin_addr));
}


  
  /* use select() to handle two descriptors at once */

  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

    if (cliserv == CLIENT) {
    printf("Available command to break: \n");
    printf("b : breaks the current VPN tunnel!!\n");
    printf("s : Changes the session key for the VPN tunnel!!\n");
    printf("i : Changes the IV for the VPN tunnel!!\n");
  }

  int r = 0;
  char buffer1[BUFSIZE];
  while(1) {
    int ret;
    fd_set rd_set;

    int ssl_fd;
    char buffer2[256];
    int readn;

   
    ssl_fd = SSL_get_fd(ssl);
    if (ssl_fd < 0) {
      perror("ssl fd");
      exit(1);
    }

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); 
    FD_SET(STDIN, &rd_set);
    FD_SET(net_fd, &rd_set);
    FD_SET(ssl_fd, &rd_set);

    maxfd = tap_fd > net_fd ? (tap_fd > STDIN ? tap_fd : STDIN) : (net_fd > STDIN ? net_fd : STDIN);
    maxfd = maxfd > ssl_fd ? maxfd : ssl_fd;

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    //do_debug("test ret== %d\n",ret);
    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }


    if (FD_ISSET(ssl_fd, &rd_set)) { // from ssl
      int len = BIO_read(sbio, session_change, 33);
      do_debug("Message from client!\n");
      if (session_change[0] == 's') {
        do_debug("New session key in progress!!!\n");
        memcpy(key, &(session_change[1]), 32);
        Hex_format_printing(key, 32);
      } else if (session_change[0] == 'i') {
        do_debug("New IV in progress!!!!\n");
        memcpy(iv, &(session_change[1]), 16);
        Hex_format_printing(iv, 16);
      } else if (session_change[0] == 'b') {
        do_debug("Break current VPN is initiated!!!\n");
        goto shutdown;
      } else {
        do_debug("unkown message- some unknown command is getting executed-Beware\n");
      }
    }
    void close1(unsigned char *messages)
    {
      BIO_flush(sbio);
      free(messages);
      do_debug("New session key sent!\n");
    }
    void close2(unsigned char *messages)
    {
    BIO_flush(sbio);
    free(messages);
    printf("New iv sent!\n");
    }
    void close3(unsigned char *messages)
    {
      BIO_flush(sbio);
      free(messages);
      printf("Break message sent\n");
    }

    if (FD_ISSET(STDIN, &rd_set)) { // from console
      if (cliserv != CLIENT) continue;
      if (r) continue;
      readn = read(STDIN, buffer2, sizeof(buffer2));
      if (readn > 0) {
        if (buffer2[0] == 's') {
          printf("OH...got command to change the session key.....lets change it to:\n");
          int i;
          for (i = 0; i < 32; i++) {
            key[i] = (unsigned char) (rand() % 256);
          }
          Hex_format_printing(key, 32);
          unsigned char *messages = (unsigned char*)malloc(33);
          messages[0] = 's';
          for (i = 0; i < 32; i++) {
            messages[i + 1] = key[i];
          }
          do_debug("Now that i have generated the new sending new session key to server\n");
          if (BIO_write(sbio, messages, 33) <= 0) {
            printf("Error in sending session key\n");
            ERR_print_errors_fp(stderr);
            exit(1);
          }
          close1(messages);
        }
        else if (buffer2[0] == 'i') {
          printf("Changing the iv to:\n");
          // generate random iv
          int i;
          for (i = 0; i < 16; i++) {
            iv[i] = (unsigned char) (rand() % 256);
          }
          Hex_format_printing(iv, 16);
          unsigned char *messages = (unsigned char*)calloc(33, sizeof(char));
          messages[0] = 'i';
          for (i = 0; i < 16; i++) {
            messages[i + 1] = iv[i];
          }
          if (BIO_write(sbio, messages, 33) <= 0) {
            do_debug("Error in sending iv\n");
            ERR_print_errors_fp(stderr);
            exit(1);
          }
            close2(messages);
        }
        else if (buffer2[0] == 'b') {
          r = 1;
          printf("Breaking the current VPN\n");
          unsigned char *messages = (unsigned char*)calloc(33, sizeof(char));
          messages[0] = 'b';
          if (BIO_write(sbio, messages, 33) <= 0) {
            do_debug("Error in sending iv\n");
            ERR_print_errors_fp(stderr);
            exit(1);
          }
          close3(messages);
        goto shutdown;
        }
        else
          do_debug("Unknown command\n");
      }
  
      else
      {
        printf("Something else is hapenning.....I need to figure this out\n");
      }
}
    
    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */

      do_debug("test tap_fd== %d\n",tap_fd);
      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      nread = encrypt (buffer, nread, key, iv, buffer1);
      unsigned char* t = generate_hmac(key, buffer1);
      memcpy(buffer1 + nread, t, 32);
      nwrite = sendto(net_fd, buffer1, nread + 32, 0, (struct sockaddr*) &remote, sizeof(remote));
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
    do_debug("test net_fd== %d\n",net_fd);

      net2tap++;

      /* read packet */
      nread = recvfrom(net_fd, buffer, BUFSIZE, 0, NULL, NULL);
      if (nread < 0) {
        perror("Reading data");
        exit(1);
      }
      //nread = read_n(net_fd, buffer, ntohs(plength));
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);


      memcpy(buffer1, buffer, nread - 32);
      if (compare_hmac(key, buffer1, buffer + nread)) {
        perror("Wrong");
        exit(1);
      }
      nread = decrypt(buffer1, nread - 32, key, iv, buffer);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, nread);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }

  shutdown:
  /* Shutdown of the SSL connection*/
  r = SSL_shutdown(ssl);
  if (!r) {
    r = SSL_shutdown(ssl);
  }
  switch (r) {
  case 1:
    goto done;
  default:
    perror("shutdown failed\n");
    exit(1);
  }

done:
  /* Close the connection and free the context */
  BIO_free_all(sbio);
  SSL_CTX_free(sslctx);

  close(net_fd);
  close(tap_fd);
  
  return(0);
}
