#include <pthread.h>
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
#include "Netsukuku-Console.h"

int sockfd, sockfd1, sendrecv;
struct sockaddr_un serveraddr;
struct sockaddr ntkdaddr;
int rc, length, exit_now;
char *request, *response;

time_t rawtime;
struct tm *timeinfo;

int uptime_sec;
int uptime_min;
int uptime_hr;

void usage();

void clean_up();

int validity_check(void) {
    
    if(request && strncmp(request, "null", (int)strlen(request)) != 0) {
    
        if(strncmp(request,"help", (int)strlen(request))  == 0)
            return 1;
        
        else if(strncmp(request,"uptime", (int)strlen(request))  == 0)
            return 0;
        
        else if(strncmp(request,"kill", (int)strlen(request))  == 0)
            return 2;
        
        else if(strncmp(request,"version", (int)strlen(request))  == 0)
            return 3;
        
        else if(strncmp(request,"console_uptime", (int)strlen(request))  == 0)
            return 4;
        
        else if(strncmp(request,"inet_connected", (int)strlen(request))  == 0)
            return 0;
        
        else if(strncmp(request,"cur_ifs", (int)strlen(request))  == 0)
            return 0;
        
        else if(strncmp(request,"cur_ifs_n", (int)strlen(request))  == 0)
            return 0;
        
        else if(strncmp(request,"cur_qspn_id", (int)strlen(request))  == 0)
            return 0;
        
        else if(strncmp(request,"cur_ip", (int)strlen(request))  == 0)
            return 0;
        
        else if(strncmp(request,"cur_node", (int)strlen(request))  == 0)
            return 0;
        
        else if(strncmp(request,"ifs", (int)strlen(request))  == 0)
            return 0;
        
        else if(strncmp(request,"ifs_n", (int)strlen(request))  == 0)
            return 0;
        
        else {
            printf("Incorrect or unreadable command, Please correct it.\n");
            return -1;
        }
    }
    
    return -2;
    
}

/* this function is run by the second thread */
void *ntkd_request(void *argv) {
    
    while(usleep(200)) {
        while(request && sendrecv == 1 && strncmp(request, "null", (int)strlen(request) != 0)) {
            rc = sendto(sockfd1, request, strlen(request), 0, (struct sockaddr *)&serveraddr, (socklen_t)sizeof(&serveraddr));
                if (rc < 0) {
                    perror("sendto() failed");
                    exit(-1);
                }

            rc = recvfrom(sockfd1, response, strlen(response), MSG_WAITALL, (struct sockaddr *)&ntkdaddr, (socklen_t *__restrict)sizeof(&ntkdaddr));
            if (rc < 0) {
                perror("recvfrom() failed");
                exit(-1);
           }

            if(rc >= 0) {
                printf("Sent and received Successfully!\n The Response was) %s", response);

       }
    
    }
  }
return 0;
}

void opensocket(void) {
    
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
        clean_up();
        opensocket();
      }
}

void console_uptime(void) {
    
    int uptime_sec1;
    int uptime_min1;
    int uptime_hr1;
    
    time(&rawtime);
    
    timeinfo = localtime(&rawtime);
    
    uptime_sec1 = timeinfo->tm_sec;
    uptime_min1 = timeinfo->tm_min;
    uptime_hr1 = timeinfo->tm_hour;
    
    uptime_sec1 -= uptime_sec;
    uptime_min1 -= uptime_min;
    uptime_hr1 -= uptime_hr;
    
    printf("Total Uptime is: %i, %i, %i\n", uptime_hr1, uptime_min1, uptime_sec1);
    
}

void console(void) {
    
    char request_buf[16];
    
    exit_now = 1;
    
    while(exit_now == 1) {
        printf("\n>");
        
        fgets(request_buf, 16, stdin);
        
        strcpy(request, request_buf);
        
        if(validity_check() == -2)
            printf("Error: Command has not been processed!");
        
        if(validity_check() == -1)
            usage();
        
        if(strncmp(request,"quit", (int)strlen(request)) == 0) {
            exit_now = 2;
            clean_up();
            exit(0);
        }
    
        if(validity_check() == 0)
            sendrecv = 1;
        
        if(validity_check() == 1)
            usage();
        
        if(validity_check() == 2)
            system("ntkd -k");
        
        if(validity_check() == 3) {
            printf("%s", VERSION_STR);
            sendrecv = 1;
        }
        
        if(validity_check() == 4)
            console_uptime();
    
        sendrecv = 0;
    }    
}

int main(void) {

    char request_buf[16];
    
    printf("\n>");
    
    fgets(request_buf, 16, stdin);
    
    printf("uhm %s", request_buf);
    
    sendrecv = 0;
    
    /*request = "null";*/
    
    time(&rawtime);
    
    timeinfo = localtime(&rawtime);
    
    uptime_sec = timeinfo->tm_sec;
    uptime_min = timeinfo->tm_min;
    uptime_hr = timeinfo->tm_hour;
    
    opensocket();
    
    printf("This is the Netsukuku Console, Please type 'help' for more information.\n");
    
/* This variable is our reference to the second thread */
    pthread_t NtkdRequest;

/* Create a second thread which executes ntkd_request() */
    if(pthread_create(&NtkdRequest, NULL, ntkd_request, 0)) {
        fprintf(stderr, "Error creating thread\n");
        return -1;
    }

/* Detach the second thread */
        if(pthread_detach(NtkdRequest)) {
            fprintf(stderr, "Error detaching thread\n");
            return -2;
        }
 
    console();
    
 return 0;
}

void usage(void) {
    
    	printf("Usage\n"
		" uptime    Returns the time when ntkd finished the hooking," 
					  "to get the the actual uptime just do) "
					  "time(0)-me.uptime \n"
		" help	Shows this\n"
		" kill	Kills the running instance of netsukuku with SIGINT\n\n"
		" version   Shows the running version of ntkd and ntk-console\n"
		" inet_connected    If it is 1, Ntkd is connected to the Internet\n"
		"\n"
		" cur_ifs   Lists all of the interfaces in cur_ifs\n"
		" cur_ifs_n Lists the number of interfaces present in `cur_ifs'\n"
		"\n");
        printf(" cur_qspn_id   The current qspn_id we are processing. "
                                "It is cur_qspn_id[levels] big\n"
		" cur_ip    Current IP address\n"
		"\n"
		" cur_node  Current Node\n"
		" ifs   Lists all of the interfaces in server_opt.ifs\n"
                " ifs_n Lists the number of interfaces present in server_opt.ifs\n"
                " quit Exits this program\n"
		" console_uptime    Gets the uptime of this console\n");
    
}

void clean_up(void) {
    
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