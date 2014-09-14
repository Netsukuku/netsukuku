/* Header files required for the console bindings
 * not included outside of this file. */


#include <utmp.h>
#include <stdio.h>
#include <sys/un.h>
#include <unistd.h>

#include "console.h"
#include "netsukuku.h"


/* Variable and structure defintions, serverfd refers to socket file descriptor
 * length refers to the required length of the requests that will be sent.
 * recv won't wake up until length is received.
 * rc is used for error checking in socket operations.
 * serveraddr is a structure describing the address of 
 * an AF_LOCAL (aka AF_UNIX) socket. */

int serverfd = -1;
struct sockaddr_un serveraddr;
int rc, length;

/* Cleans up the console bindings for closing, Closes socket file descriptors,
 * unlinks the server path, etc. */

static void
clean_up(void)
{
	const int optVal = 1;
	const socklen_t optLen = sizeof(optVal);
	
	setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen);
	
	if (serverfd != -1)
		close(serverfd);

   unlink(CONSOLE_SOCKET_PATH);
	
}

/* Creates an AF_UNIX socket and binds it to a local address. */

static void
opensocket(void)
{
	int stop_trying;
	
	serverfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (serverfd < 0) {
		 perror("socket creation failed");
		 exit(-1);
	}
	
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strcpy(serveraddr.sun_path, CONSOLE_SOCKET_PATH);

	rc = bind(serverfd, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr));
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

static void
send_response(int session_fd, char response[CONSOLE_BUFFER_LENGTH], ...)
{
	int response_length = (int)strlen(response);
	rc = send(session_fd, response, response_length, 0);
	if (rc < 0){
		perror("send() failed");
		exit(-1);
	}
}


/* Parses the received request from the ntk console client
 * to data from ntkd structures such as: me 
 * into a response for the ntk console client. */

static int
request_processing(int session_fd, char unprocessed_request[CONSOLE_BUFFER_LENGTH])
{
	if(strncmp(unprocessed_request,"uptime", (int)strlen(unprocessed_request))  == 0)
		send_response(session_fd, (char)time(0)-me.uptime);
	
	else if(strncmp(unprocessed_request,"version", (int)strlen(unprocessed_request))  == 0)
		send_response(session_fd, VERSION_STR);
	
	else if(strncmp(unprocessed_request,"inet_connected", (int)strlen(unprocessed_request))  == 0)
		send_response(session_fd, (char)me.inet_connected);
	
	else if(strncmp(unprocessed_request,"cur_ifs", (int)strlen(unprocessed_request))  == 0)
		send_response(session_fd, (char)me.cur_ifs);
		
	else if(strncmp(unprocessed_request,"cur_ifs_n", (int)strlen(unprocessed_request))  == 0)
		send_response(session_fd, (char)me.cur_ifs_n);
		
	else if(strncmp(unprocessed_request,"cur_qspn_id", (int)strlen(unprocessed_request))  == 0)
		send_response(session_fd, (char)me.cur_qspn_id);
		
	else if(strncmp(unprocessed_request,"cur_ip", (int)strlen(unprocessed_request))  == 0)
		send_response(session_fd, (char)me.cur_ip.data);
		
	/*else if(strncmp(unprocessed_request,"cur_node", (int)strlen(unprocessed_request))  == 0)
		send_response(me.cur_node);
		
	else if(strncmp(unprocessed_request,"ifs", (int)strlen(unprocessed_request))  == 0)
		return 0;
		
	else if(strncmp(unprocessed_request,"ifs_n", (int)strlen(unprocessed_request))  == 0)
		return 0;*/
	send_response(session_fd, unprocessed_request, " Is invalid or yet to be implemented.");
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


static void
handle_session(int session_fd)
{
	char request[CONSOLE_BUFFER_LENGTH];

	rc = request_receive(session_fd, request, CONSOLE_BUFFER_LENGTH);
	if (rc < 0) {
		perror("recv() failed");
		exit(-1);
	}
	
	printf("%d bytes of data were received\n", rc);
	
	request_processing(session_fd, request);
}


static void
wait_session(int server_fd)
{
	rc = listen(serverfd, 10);
	if (rc< 0) {
		perror("listen() failed");
		exit(-1);
	}

	printf("Ready for client connect().\n");

	for(;;) {
		int session_fd = accept(server_fd, NULL, NULL);
		if (session_fd < 0) {
			perror("accept() failed");
			exit(-1);
		}

		pid_t pid = fork();
		if (pid == -1) {
			perror("Failed to spawn child console process");
			exit(-1);
		} else if (pid == 0) {
			close(server_fd);
			handle_session(session_fd);
			_exit(0);
		} else {
			close(session_fd);
		}

	}
}


void*
console_recv_send(void *arg)
{
	char* uargv;

	opensocket();
	wait_session(serverfd);

	return uargv;
}
