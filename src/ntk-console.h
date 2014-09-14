#ifndef NETSUKUKUCONSOLE_H
#define NETSUKUKUCONSOLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <utmp.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>


#define SERVER_PATH 		"/tmp/ntk-console"
#define BUFFER_LENGTH 		250
#define VERSION_STR 		"0.0.2"

#ifndef TRUE
#define FALSE 				0
#define TRUE 				1
#endif


typedef enum {
	COMMAND_HELP = 0x100,
	COMMAND_UPTIME,
	COMMAND_KILL,
	COMMAND_VERSION,
	COMMAND_INETCONN,
	COMMAND_CURIFS,
	COMMAND_CURIFSCT,
	COMMAND_CURQSPNID,
	COMMAND_CURIP,
	COMMAND_CURNODE,
	COMMAND_IFS,
	COMMAND_IFSCT,
	COMMAND_QUIT,
	COMMAND_CONSUPTIME,
} command_t;


int sockfd = -1, sockfd1 = -1;
struct sockaddr_un serveraddr;
int rc, bytesReceived;

time_t rawtime;
struct tm *timeinfo;

int uptime_sec;
int uptime_min;
int uptime_hour;
int uptime_day;
int uptime_month;
int uptime_year;

int i;

void usage();
void clean_up();

void opensocket();
void closesocket();


#endif /*NETSUKUKUCONSOLE_H*/
