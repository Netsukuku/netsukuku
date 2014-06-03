#ifndef NETSUKUKUCONSOLE_H
#define NETSUKUKUCONSOLE_H

#define SERVER_PATH     "/tmp/server"
#define VERSION_STR     "0.0.1"
#define FALSE              0

extern int sockfd, sockfd1, sendrecv = 0;
extern struct sockaddr_un serveraddr;
extern struct sockaddr ntkdaddr;
extern int rc, length;
extern char *request, *response;

#endif /*NETSUKUKUCONSOLE_H*/