/* This file is part of Netsukuku
 *
 * This source code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * Please refer to the GNU Public License for more details.
 *
 * You should have received a copy of the GNU Public License along with
 * this source code; if not, write to:
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


#include "ntk-console.h"
#include "console.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>


const struct supported_commands {
	command_t id;
	const char *command;
	const char *help;
	int arguments;
} kSupportedCommands[] = {
	{
	COMMAND_HELP, "help", "Shows console help", 0}, {
	COMMAND_UPTIME, "uptime",
			"Returns the time when ntkd finished the hooking", 0}, {
	COMMAND_KILL, "kill",
			"Kills the running instance of netsukuku with SIGINT", 0}, {
	COMMAND_VERSION, "version",
			"Shows the running version of the ntk-console, and ntkd.", 0},
	{
	COMMAND_INETCONN, "inet_connected",
			"Query if Ntkd is connected to the internet", 0}, {
	COMMAND_CURIFS, "cur_ifs",
			"Lists all of the interfaces in cur_ifs", 0}, {
	COMMAND_CURIFSCT, "cur_ifs_n",
			"Lists the number of interfaces present in `cur_ifs`", 0}, {
	COMMAND_CURQSPNID, "cur_qspn_id",
			"The current qspn_id we are processing. It is cur_qspn_id[levels] big",
			0}, {
	COMMAND_CURIP, "cur_ip", "Current IP address", 0}, {
	COMMAND_CURNODE, "cur_node", "Current node", 0}, {
	COMMAND_IFS, "ifs", "List all the interfaces in server_opt.ifs", 0}, {
	COMMAND_IFSCT, "ifs_n",
			"List the number of interfaces present in server_opt.ifs", 0},
	{
	COMMAND_QUIT, "quit", "Exit the console", 0}, {
COMMAND_CONSUPTIME, "console_uptime",
			"Get the uptime of this console", 0},};


command_t
command_parse(char *request)
{
	if (strlen(request) > CONSOLE_BUFFER_LENGTH) {
		printf("Error: Command longer than 250 bytes.\n");
		return -1;
	}

	for (int i = 0; i < sizeof(kSupportedCommands)
		 / sizeof(kSupportedCommands[0]); i++) {
		if (strncmp(request, kSupportedCommands[i].command,
					(int) strlen(request) - 1) == 0) {
			return kSupportedCommands[i].id;
		}
	}

	printf("Incorrect or unreadable command, Please correct it.\n");
	return -1;
}


static int
request_receive(int sock, char message[], int max)
{
	int total = 0;
	const int bsize = 1024;
	char buffer[bsize + 1];
	int read = bsize;

	message[0] = 0;				// initialize for strcat()

	while (read == bsize) {
		read = recv(sock, buffer, bsize, 0);
		if (read < 0)
			return -1;			// error, bail out
		total += read;
		if (total > max)
			return -2;			// overflow
		buffer[read] = 0;
		strcat(message, buffer);
	}

	return total;
}


int
opensocket(void)
{
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket creation failed");
		return -1;
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strcpy(serveraddr.sun_path, CONSOLE_SOCKET_PATH);

	rc = connect(sockfd, (struct sockaddr *) &serveraddr,
				 sizeof(serveraddr));
	if (rc < 0) {
		perror("connect() failed");
		return -1;
	}
	return 0;
}


void
closesocket(void)
{
	const int optVal = 1;
	const socklen_t optLen = sizeof(optVal);

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &optVal, optLen);

	if (sockfd >= 0)
		close(sockfd);
}


/* Sends and receives to ntkd */
void
ntkd_request(command_t command)
{
	if (opensocket() < 0) {
		printf("Unable to connect to ntk daemon console.\n");
		return;
	}

	cmd_packet_t packetOut;
	packetOut.command = command;

	rc = send(sockfd, &packetOut, sizeof(packetOut), 0);
	if (rc < sizeof(packetOut)) {
		perror("send() failed");
		exit(-1);
	}

	char *response = (char *) malloc(CONSOLE_BUFFER_LENGTH);
	request_receive(sockfd, response, CONSOLE_BUFFER_LENGTH);
	if (rc < 0) {
		perror("recv() failed");
		exit(-1);
	}

	printf("%s\n", response);
	free(response);
	closesocket();
}


void
console_uptime(void)
{
	int uptime_sec1;
	int uptime_min1;
	int uptime_hour1;

	int uptime_day1;
	int uptime_month1;
	int uptime_year1;

	time(&rawtime);

	timeinfo = localtime(&rawtime);

	uptime_sec1 = timeinfo->tm_sec;
	uptime_min1 = timeinfo->tm_min;
	uptime_hour1 = timeinfo->tm_hour;

	uptime_day1 = timeinfo->tm_mday;
	uptime_month1 = timeinfo->tm_mon;
	uptime_year1 = timeinfo->tm_year;

	uptime_sec1 -= uptime_sec;
	uptime_min1 -= uptime_min;
	uptime_hour1 -= uptime_hour;

	uptime_day1 -= uptime_day;
	uptime_month1 -= uptime_month;
	uptime_year1 -= uptime_year;

	printf
		("Total Uptime is: %i Year(s), %i Month(s), %i Day(s), %i Hour(s), %i Minute(s), %i Second(s)\n",
		 uptime_year1, uptime_month1, uptime_day1, uptime_hour1,
		 uptime_min1, uptime_sec1);
}


static void
millisleep(unsigned ms)
{
	usleep(1000 * ms);
}


void
console(char *request)
{
	command_t commandID = command_parse(request);

	switch (commandID) {
	case COMMAND_QUIT:
		closesocket();
		exit(0);
		break;
	case COMMAND_UPTIME:
	case COMMAND_INETCONN:
	case COMMAND_CURIFS:
	case COMMAND_CURIFSCT:
	case COMMAND_CURQSPNID:
	case COMMAND_CURIP:
	case COMMAND_CURNODE:
	case COMMAND_IFS:
	case COMMAND_IFSCT:
		ntkd_request(commandID);
		millisleep(200);
		break;
	case COMMAND_VERSION:
		printf("ntk-console version: %d.%d\n",
			   CONSOLE_VERSION_MAJOR, CONSOLE_VERSION_MINOR);
		ntkd_request(commandID);
		break;
	case COMMAND_CONSUPTIME:
		console_uptime();
		break;
	case COMMAND_KILL:
		closesocket();
		system("ntkd -k");
		break;
	case COMMAND_HELP:
	default:
		usage();
	}
}


int
main(void)
{
	time(&rawtime);

	timeinfo = localtime(&rawtime);

	uptime_sec = timeinfo->tm_sec;
	uptime_min = timeinfo->tm_min;
	uptime_hour = timeinfo->tm_hour;
	uptime_day = timeinfo->tm_mday;
	uptime_month = timeinfo->tm_mon;
	uptime_year = timeinfo->tm_year;

	printf
		("This is the Netsukuku Console. Please type 'help' for more information.\n");
	for (;;) {
		char *request = (char *) malloc(CONSOLE_BUFFER_LENGTH);
		printf("\n> ");
		fgets(request, 16, stdin);
		fflush(stdin);
		console(request);
		free(request);
		closesocket();
	}

	return 0;
}

void
usage(void)
{
	printf("Usage:\n");
	for (int i = 0; i < sizeof(kSupportedCommands)
		 / sizeof(kSupportedCommands[0]); i++) {
		printf("  %16s - %s\n", kSupportedCommands[i].command,
			   kSupportedCommands[i].help);
	}
}
