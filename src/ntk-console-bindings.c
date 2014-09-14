/* Header files required for the console bindings
 * not included outside of this file. */

#include <utmp.h>
#include <sys/un.h>
#include <unistd.h>

#include "netsukuku.h"

/* Constants used for the console bindings. */

#define SERVER_PATH	 "/tmp/ntk-console"
#define REQUEST_LENGTH   250
#define FALSE 			0
#define TRUE 			1

/* Variable and structure defintions, sockfd refers to socket file descriptor
 * length refers to the required length of the requests that will be sent.
 * recv won't wake up until length is received.
 * rc is used for error checking in socket operations.
 * serveraddr is a structure describing the address of 
 * an AF_LOCAL (aka AF_UNIX) socket. */

int sockfd_1 = -1, sockfd_2 = -1;
struct sockaddr_un serveraddr;
int rc, length;

/* Cleans up the console bindings for closing, Closes socket file descriptors,
 * unlinks the server path, etc. */

void clean_up(void) {
	
	const int optVal = 1;
	const socklen_t optLen = sizeof(optVal);
	
	setsockopt(sockfd_1, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen);
	setsockopt(sockfd_2, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen);
	
	if (sockfd_1 != -1)
		close(sockfd_1);

	if (sockfd_2 != -1)
		close(sockfd_2);
   
   unlink(SERVER_PATH);
	
}

/* Creates an AF_UNIX socket and binds it to a local address. */

void opensocket(void) {
	
	int stop_trying;
	
	sockfd_1 = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd_1 < 0) {
		 perror("socket creation failed");
		 exit(-1);
	}
	
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strcpy(serveraddr.sun_path, SERVER_PATH);

	rc = bind(sockfd_1, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr));
	if (rc < 0) {
		perror("bind() failed");
		clean_up();
		if(stop_trying >= 2) {
			perror("bind() failed");
			clean_up();
			opensocket();
			exit(-1);
		}
		stop_trying++;
		opensocket();
	}
}

/* Sends a parsed response to the ntk console client. */

void
send_response(char response[REQUEST_LENGTH], ...)
{
	int response_length = (int)strlen(response);
	rc = send(sockfd_2, response, sizeof(response), 0);
	if (rc < 0){
		perror("send() failed");
		exit(-1);
	}
}


/* Parses the received request from the ntk console client
 * to data from ntkd structures such as: me 
 * into a response for the ntk console client. */

int
request_processing(char unprocessed_request[REQUEST_LENGTH])
{
	if(strncmp(unprocessed_request,"uptime", (int)strlen(unprocessed_request))  == 0)
		send_response((char)time(0)-me.uptime);
	
	else if(strncmp(unprocessed_request,"version", (int)strlen(unprocessed_request))  == 0)
		send_response(VERSION_STR);
	
	else if(strncmp(unprocessed_request,"inet_connected", (int)strlen(unprocessed_request))  == 0)
		send_response((char)me.inet_connected);
	
	else if(strncmp(unprocessed_request,"cur_ifs", (int)strlen(unprocessed_request))  == 0)
		send_response((char)me.cur_ifs);
		
	else if(strncmp(unprocessed_request,"cur_ifs_n", (int)strlen(unprocessed_request))  == 0)
		send_response((char)me.cur_ifs_n);
		
	else if(strncmp(unprocessed_request,"cur_qspn_id", (int)strlen(unprocessed_request))  == 0)
		send_response((char)me.cur_qspn_id);
		
	else if(strncmp(unprocessed_request,"cur_ip", (int)strlen(unprocessed_request))  == 0)
		send_response((char)me.cur_ip.data);
		
	/*else if(strncmp(unprocessed_request,"cur_node", (int)strlen(unprocessed_request))  == 0)
		send_response(me.cur_node);
		
	else if(strncmp(unprocessed_request,"ifs", (int)strlen(unprocessed_request))  == 0)
		return 0;
		
	else if(strncmp(unprocessed_request,"ifs_n", (int)strlen(unprocessed_request))  == 0)
		return 0;*/
	send_response(unprocessed_request, " Is invalid or yet to be implemented.");
	return -1;
}


static int
request_receive(int sock, char message[], int max)
{
	int total = 0;
	const int bsize = 1024;
	char buffer[bsize+1];
	int read = bsize;
	 
	message[0] = 0; // initialize for strcat()
	
	while(read == bsize) {
		read = recv(sock, buffer, bsize, 0);
		if(read < 0)
			return -1; // error, bail out
		total += read;
		if(total > max)
			return -2; // overflow
		buffer[read] = 0;
		strcat(message, buffer);
	}
	     
	return total;
}


void ntkd_request(void) {
	char request[REQUEST_LENGTH];
	
	rc = listen(sockfd_1, 10);
	if (rc< 0) {
		perror("listen() failed");
		exit(-1);
	}

	printf("Ready for client connect().\n");

	do {
		sockfd_2 = accept(sockfd_1, NULL, NULL);
		if (sockfd_2 < 0) {
			perror("accept() failed");
			exit(-1);
		}

		rc = request_receive(sockfd_2, request, REQUEST_LENGTH);
		if (rc < 0) {
			perror("recv() failed");
			exit(-1);
		}
		
		printf("%d bytes of data were received\n", rc);
		
		request_processing(request);
	} while(TRUE);
		
	clean_up();
}

void console_recv_send(void) {
	opensocket();
	ntkd_request();
}
