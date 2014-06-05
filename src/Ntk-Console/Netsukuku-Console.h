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

#define SERVER_PATH     "/tmp/ntk-console"
#define VERSION_STR     "0.0.1"
#define FALSE              0

int sockfd, sockfd1, sendrecv;
struct sockaddr_un serveraddr;
struct sockaddr ntkdaddr;
int rc, length, exit_now;
char *request, *response;

time_t rawtime;
struct tm *timeinfo;

int uptime_sec;
int uptime_min;
int uptime_hour;
int uptime_day;
int uptime_month;
int uptime_year;

void usage();

void clean_up();

#endif /*NETSUKUKUCONSOLE_H*/