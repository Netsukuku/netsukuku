#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "Netsukuku-Console.h"

void usage();

int validity_check(char argv) {
    
    switch(argv) {
        case 'help':
            return 1;
            break;
        case 'uptime':
            return 0;
            break;
        case 'kill':
            return 2;
            break;
        case 'version':
            return 3;
            break;
        case 'inet_connected':
            return 0;
            break;
        case 'cur_ifs':
            return 0;
            break;
        case 'cur_ifs_n':
            return 0;
            break;
        case 'cur_qspn_id':
            return 0;
            break;
        case 'cur_ip':
            return 0;
            break;
        case 'cur_node':
            return 0;
            break;
        case 'ifs':
            return 0;
            break;
        case 'ifs_n':
            return 0;
            break;
        case 'console_uptime':
            return 0;
            break;
        default:
            printf("Incorrect or unreadable command, Please correct it.\n");
            return -1;
            break;    
    }
    
}

/* this function is run by the second thread */
void *ntkd_request(void *argv) {
    
    while(sendrecv == 1) {
        rc = sendto(sockfd1, request, strlen(request), 0, (struct sockaddr *)&serveraddr, strlen(serveraddr));
            if (rc < 0) {
                perror("sendto() failed");
                exit(-1);
            }
    
        rc = recvfrom(sockfd1, response, strlen(response), MSG_WAITALL, (struct sockaddr *)&ntkdaddr, strlen(ntkdaddr));
        if (rc < 0) {
            perror("recvfrom() failed");
            exit(-1);
        }
    
        if(rc >= 0) {
            printf("Sent and received Successfully!\n The Response was: %s", response);
            
        }
    
    }
}

int opensocket(void) {
    
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
         perror("socket creation failed");
         exit(-1);
    }
    
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, SERVER_PATH);

    rc = bind(sockfd, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr));
    if (rc < 0) {
        perror("bind() failed");
        exit(-1);
      }
}

int console(void *argv) {
    
    int exit_now = 0;
    
    while(exit_now == 1) {
        printf("\n>")
    
        request = scanf("%s");
        
        if(validity_check(request) == -1)
            usage();
        
        if(strncmp(request, "quit", 4) == 0)
            exit(0);
    
        if(validity_check(request) == 0)
            sendrecv = 1;
        
        if(validity_check(request) == 1)
            usage();
        
        if(validity_check(request) == 2)
            system("ntkd -k");
        
        if(validity_check(request) == 3) {
            printf("%s", VERSION_STR);
            sendrecv = 1;
        }
    
        sendrecv = 0;
    }    
}

int main(void) {
    
    opensocket();
    
    printf("This is the Netsukuku Console, Please type: 'help' for more information.\n");
    
/* This variable is our reference to the second thread */
    pthread_t NtkdRequest;

/* Create a second thread which executes ntkd_request() */
    if(pthread_create(&NtkdRequest, NULL, ntkd_request, NULL)) {
        fprintf(stderr, "Error creating thread\n");
        return -1;
    }

/* Detach the second thread */
    if(pthread_detach(NtkdRequest)) {
        fprintf(stderr, "Error joining thread\n");
        return -2;
    }
    
    pthread_t ConsoleThread;
    
    if(pthread_create(&ConsoleThread, NULL, console, NULL)) {
        fprintf(stderr, "Error creating thread\n");
        return -1;
    }

    if(pthread_detach(ConsoleThread)) {
        fprintf(stderr, "Error joining thread\n");
        return -2;
    }

return 0;

}

void usage(void) {
    
    	printf("Usage:\n"
		" uptime    Returns the time when ntkd finished the hooking, 
					  "to get the the actual uptime just do: "
					  "time(0)-me.uptime \n"
		" help	Shows this\n"
		" kill	Kills the running instance of netsukuku with SIGINT\n\n"
		" version   Shows the running version of ntkd and ntk-console\n"
		" inet_connected    If it is 1, Ntkd is connected to the Internet\n"
		"\n"
		" cur_ifs   Lists all of the interfaces in cur_ifs\n"
		" cur_ifs_n Lists the number of interfaces present in `cur_ifs'\n"
		"\n"
		" cur_qspn_id   The current qspn_id we are processing. "
                                "It is cur_qspn_id[levels] big\n"
		" cur_ip    Current IP address\n"
		"\n"
		" cur_node  Current Node\n"
		" ifs   Lists all of the interfaces in server_opt.ifs\n"
                " ifs_n Lists the number of interfaces present in server_opt.ifs\n"
                " quit Exits this program\n"
		" console_uptime    Gets the uptime of this console (Yet to be implemented)\n");
    
}