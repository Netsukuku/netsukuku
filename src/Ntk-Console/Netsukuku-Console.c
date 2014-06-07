#include "Netsukuku-Console.h"

char *response;

void usage();

void clean_up();

int validity_check(char *request) {
    
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
    
    return -2;
    
}

/* this function is run by the second thread */
void ntkd_request(char *request) {

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

void console(char *request) { 
    
    printf("%s", request);
        
    if(validity_check(request) == -2)
            printf("Error: Command has not been processed!");
        
    if(validity_check(request) == -1)
            usage();
        
    if(strncmp(request,"quit", (int)strlen(request)) == 0) {
            clean_up();
            exit(0);
        }
    
    if(validity_check(request) == 0)
            ntkd_request(request);
        
    if(validity_check(request) == 1)
            usage();
        
    if(validity_check(request) == 2)
            /*system("ntkd -k");*/
        printf("");
        
    if(validity_check(request) == 3) {
            printf("%s", VERSION_STR);
            ntkd_request(request);
        }

    if(validity_check(request) == 4)
            console_uptime();  
}

int main(void) {
    
    /*time(&rawtime);
    
    timeinfo = localtime(&rawtime);
    
    uptime_sec = timeinfo->tm_sec;
    uptime_min = timeinfo->tm_min;
    uptime_hour = timeinfo->tm_hour;
    uptime_day = timeinfo->tm_mday;
    uptime_month = timeinfo->tm_mon;
    uptime_year = timeinfo->tm_year;
    
    opensocket();
    
    printf("This is the Netsukuku Console, Please type 'help' for more information.\n");*/
    
    char *request;
    
    int exit_now;
    
    exit_now = 1;
    
    while(exit_now == 1) {
    
    printf("\n>");
        
    fgets(request, 16, stdin);
    
    perror("fgets failed");
    
    fflush(stdin);
    
    printf("%s", request);
    
    request[strlen(request)-1] = '\0';
    
    printf("%s", request);
    
    /*console(request);*/
    }
    
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