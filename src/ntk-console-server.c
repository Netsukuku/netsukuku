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

static void
request_processing(int session_fd, cmd_packet_t packet)
{
	char buffer[CONSOLE_BUFFER_LENGTH];
	int maxBuffer = CONSOLE_BUFFER_LENGTH - 1;

	switch (packet.command) {
		case COMMAND_UPTIME:
		{
			int uptime = time(0) - me.uptime;
			snprintf(buffer, maxBuffer, "node uptime: %d seconds", uptime);
			break;
		}
		case COMMAND_VERSION:
			snprintf(buffer, maxBuffer, "ntkd version: %s", VERSION_STR);
			break;
		case COMMAND_CURIFS:
			//send_response(session_fd, (char)me.cur_ifs);
			break;
		case COMMAND_CURIFSCT:
			snprintf(buffer, maxBuffer, "current interface count: %d", me.cur_ifs_n);
			break;
		case COMMAND_INETCONN:
			//send_response(session_fd, (char)me.inet_connected);
			break;
		case COMMAND_CURQSPNID:
			//send_response(session_fd, (char)me.cur_qspn_id);
			break;
		case COMMAND_CURIP:
			//send_response(session_fd, (char)me.cur_ip.data);
			break;
		case COMMAND_CURNODE:
			//send_response(session_fd, (char)me.cur_node);
			break;
		case COMMAND_IFS:
			//send_response(session_fd, "IFS: TODO");
			break;
		case COMMAND_IFSCT:
			//send_response(session_fd, "IFS: TODO");
			break;
		default:
			snprintf(buffer, maxBuffer, "Provided command is invalid or not implemented in this API");
			break;
	}
	send_response(session_fd, buffer);
}



static void
handle_session(int session_fd)
{
	cmd_packet_t packetIn;

	rc = recv(session_fd, &packetIn, sizeof(packetIn), 0);

	if (rc < sizeof(packetIn)) {
		perror("recv() failed");
		exit(-1);
	}
	
	request_processing(session_fd, packetIn);
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
	char* uargv = NULL;

	opensocket();
	wait_session(serverfd);

	return uargv;
}
