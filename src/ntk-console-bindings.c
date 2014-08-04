#include <utmp.h>
#include <sys/un.h>
#include <unistd.h>

#include "netsukuku.h"

#define SERVER_PATH     "/tmp/ntk-console"

int sockfd_1, sockfd_2;
struct sockaddr_un serveraddr;
struct sockaddr ntkdaddr;
int rc;

int millisleep(unsigned ms)
{
  return usleep(1000 * ms);
}

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

void send_response(char *response, ...) {
    
        rc = sendto(sockfd_1, response, strlen(response), 0, (struct sockaddr *)&serveraddr, (socklen_t)sizeof(&serveraddr));
        if (rc < 0) {
        perror("sendto() failed");
        exit(-1);
        }
    
}

int request_processing(char *unprocessed_request) {
    
        if(strncmp(unprocessed_request,"uptime", (int)strlen(unprocessed_request))  == 0)
            send_response((char*)time(0)-me.uptime);
        
        else if(strncmp(unprocessed_request,"version", (int)strlen(unprocessed_request))  == 0)
            send_response(VERSION_STR);
        
        else if(strncmp(unprocessed_request,"inet_connected", (int)strlen(unprocessed_request))  == 0)
            send_response((char*)me.inet_connected);
        
        else if(strncmp(unprocessed_request,"cur_ifs", (int)strlen(unprocessed_request))  == 0)
            send_response((char*)me.cur_ifs);
        
        else if(strncmp(unprocessed_request,"cur_ifs_n", (int)strlen(unprocessed_request))  == 0)
            send_response((char*)me.cur_ifs_n);
        
        else if(strncmp(unprocessed_request,"cur_qspn_id", (int)strlen(unprocessed_request))  == 0)
            send_response((char*)me.cur_qspn_id);
        
        else if(strncmp(unprocessed_request,"cur_ip", (int)strlen(unprocessed_request))  == 0)
            send_response((char*)me.cur_ip.data);
        
        /*else if(strncmp(unprocessed_request,"cur_node", (int)strlen(unprocessed_request))  == 0)
            send_response(me.cur_node);
        
        else if(strncmp(unprocessed_request,"ifs", (int)strlen(unprocessed_request))  == 0)
            return 0;
        
        else if(strncmp(unprocessed_request,"ifs_n", (int)strlen(unprocessed_request))  == 0)
            return 0;*/
    send_response(unprocessed_request, " Is invalid or yet to be implemented.");
    return -1;
}

/* Sends and receives to the ntk console */
void ntkd_request(void) {
    
    char *request;
    
        while(0 == 0) {
            
            millisleep(100);
            
            request = 0;
            
            rc = recvfrom(sockfd_1, request, strlen(request), MSG_WAITALL, (struct sockaddr *)&ntkdaddr, (socklen_t *__restrict)sizeof(&ntkdaddr));
                if (rc < 0) {
                    perror("recvfrom() failed");
                    exit(-1);
                }
            
            if(request != 0)
                request_processing(request);
            
        }
}

int console_recv_send(void) {
    
}
