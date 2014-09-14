#include "Netsukuku-Console.h"

char response[BUFFER_LENGTH];

void usage();

void clean_up();


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


const struct supported_commands {
	command_t 		id;
	const char* 	command;
	const char* 	help;
	int 			arguments;
} kSupportedCommands[] = {
	{COMMAND_HELP, 		"help", 			"Shows console help", 0},
	{COMMAND_UPTIME, 	"uptime", 			"Returns the time when ntkd finished the hooking", 0},
	{COMMAND_KILL, 		"kill", 			"Kills the running instance of netsukuku with SIGINT", 0},
	{COMMAND_VERSION, 	"version", 			"Shows the running version of the ntk-console, and ntkd.", 0},
	{COMMAND_INETCONN, 	"inet_connected", 	"Query if Ntkd is connected to the internet", 0},
	{COMMAND_CURIFS, 	"cur_ifs", 			"Lists all of the interfaces in cur_ifs", 0},
	{COMMAND_CURIFSCT, 	"cur_ifs_n", 		"Lists the number of interfaces present in `cur_ifs`", 0},
	{COMMAND_CURQSPNID, "cur_qspn_id", 		"The current qspn_id we are processing. It is cur_qspn_id[levels] big", 0},
	{COMMAND_CURIP, 	"cur_ip", 			"Current IP address", 0},
	{COMMAND_CURNODE,	"cur_node", 		"Current node", 0},
	{COMMAND_IFS, 		"ifs", 				"List all the interfaces in server_opt.ifs", 0},
	{COMMAND_IFSCT, 	"ifs_n", 			"List the number of interfaces present in server_opt.ifs", 0},
	{COMMAND_QUIT, 		"quit", 			"Exit the console", 0},
	{COMMAND_CONSUPTIME,"console_uptime", 	"Get the uptime of this console", 0},
};


command_t
command_parse(char *request)
{
	if (strlen(request) > BUFFER_LENGTH) {
		printf("Error: Command longer than 250 bytes.\n");
		return -1;
	}

	for (int i = 0; i < sizeof(kSupportedCommands)
		/ sizeof(kSupportedCommands[0]); i++) {
		if (strncmp(request, kSupportedCommands[i].command,
			(int)strlen(request) - 1) == 0) {
			return kSupportedCommands[i].id;
		}
	}

	printf("Incorrect or unreadable command, Please correct it.\n");
	return -1;
}


void
response_cleanup(char response[BUFFER_LENGTH])
{
	char remove = 'a';

	char* c;
	char* pPosition;
	while((pPosition = strchr(response, 'a')) != NULL)  {
		if ((c = index(response, remove)) != NULL) {
		size_t len_left = sizeof(response) - (c+1-response);
		memmove(c, c+1, len_left);
		}
	}

	printf("Sent and received Successfully!\n The Response was: %s", response);
}


/* Sends and receives to ntkd */
void
ntkd_request(char *request)
{
	rc = connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
	if (rc < 0) {
		perror("connect() failed");
		exit(-1);
	}

	int request_length = strlen(request);
	memset(request, 'a', BUFFER_LENGTH - request_length);
	rc = send(sockfd, request, sizeof(request), 0);
	if (rc < 0) {
		perror("send() failed");
		exit(-1);
	}

	bytesReceived = 0;
	while (bytesReceived < BUFFER_LENGTH) {
		rc = recv(sockfd, & response[bytesReceived],
		   BUFFER_LENGTH - bytesReceived, 0);
		if (rc < 0) {
			perror("recv() failed");
			exit(-1);
		}
	else if (rc == 0) {
		printf("The server closed the connection\n");
		exit(-1);
	}

	/* Increment the number of bytes that have been received so far  */
	bytesReceived += rc;		
	}
	response_cleanup(response);
}


void
opensocket(void)
{
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		 perror("socket creation failed");
		 exit(-1);
	}
	
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strcpy(serveraddr.sun_path, SERVER_PATH);
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
	
	printf("Total Uptime is: %i Year(s), %i Month(s), %i Day(s), %i Hour(s), %i Minute(s), %i Second(s)\n",uptime_year1, uptime_month1, uptime_day1, uptime_hour1, uptime_min1, uptime_sec1);
}


int
millisleep(unsigned ms)
{
  return usleep(1000 * ms);
}


void
console(char* request)
{
	command_t commandID = command_parse(request);

	switch (commandID) {
		case COMMAND_QUIT:
			clean_up();
			exit(0);
		case COMMAND_UPTIME:
		case COMMAND_INETCONN:
		case COMMAND_CURIFS:
		case COMMAND_CURIFSCT:
		case COMMAND_CURQSPNID:
		case COMMAND_CURIP:
		case COMMAND_CURNODE:
		case COMMAND_IFS:
		case COMMAND_IFSCT:
			ntkd_request(request);
			millisleep(200);
			break;
		case COMMAND_VERSION:
			printf("Ntk-Console Version: %s\n", VERSION_STR);
			ntkd_request(request);
			break;
		case COMMAND_CONSUPTIME:
			console_uptime();
			break;
		case COMMAND_KILL:
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
	
	opensocket();
	
	printf("This is the Netsukuku Console, Please type 'help' for more information.\n");
	
	char* request = (char*)malloc(BUFFER_LENGTH);
	
	do {
		printf("\n>");
		fgets(request, 16, stdin);
		fflush(stdin);
		console(request);
	} while(FALSE);
	
	clean_up(); 
	return 0;
}

void usage(void) {
	
		printf("Usage\n"
		"  uptime         Returns the time when ntkd finished the hooking,\n" 
		"                 to get the the actual uptime just do)\n"
		"                 time(0)-me.uptime \n"
		"  help           Shows this\n"
		"  kill           Kills the running instance of netsukuku with SIGINT\n\n"
		"  version        Shows the running version of the ntk-console, and ntkd.\n"
		"  inet_connected If it is 1, Ntkd is connected to the Internet\n"
		" \n"
		"  cur_ifs        Lists all of the interfaces in cur_ifs\n"
		"  cur_ifs_n      Lists the number of interfaces present in `cur_ifs'\n"
		"  cur_qspn_id    The current qspn_id we are processing. "
		"                 It is cur_qspn_id[levels] big\n"
		"  cur_ip         Current IP address\n"
		" \n"
		"  cur_node       Current Node\n"
		"  ifs            Lists all of the interfaces in server_opt.ifs\n"
		"  ifs_n          Lists the number of interfaces present in server_opt.ifs\n"
		"  quit           Exits this program\n"
		"  console_uptime Gets the uptime of this console\n");
	
}

void clean_up(void)
{
	const int optVal = 1;
	const socklen_t optLen = sizeof(optVal);
	
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen);
	setsockopt(sockfd1, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen);
	
	if (sockfd != -1)
		close(sockfd);

	if (sockfd1 != -1)
		close(sockfd1);
   
	unlink(SERVER_PATH);
}
