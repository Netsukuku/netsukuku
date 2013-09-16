#ifndef NTK_RESOLV_H
#define NTK_RESOLV_H

#include <errno.h>
#include <netdb.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "andns_lib.h"

#define VERSION			"0.3.3"
#define NTK_RESOLV_MAIL_BUGS	"efphe@netsukuku.org"

#define NTKRESOLV_PORT		53
#define NTKRESOLV_PORT_STR	"53"
#define MAX_NS			3
#define LOCALHOST		"localhost"

#define NTK_RESOLV_TIMEOUT	15

#define MAX_HOSTNAME_LEN	512
#define NTKRESOLV_MAX_OBJ_LEN	512


//#define ANDNS_MAX_SZ    1024

#define min(x,y)		(x)<(y)?(x):(y)

#define REALM_NTK		0+1
#define REALM_INT		1+1
#define REALM_NTK_STR		"ntk"
#define REALM_INT_STR		"inet"

#define QTYPE_A			AT_A
#define QTYPE_PTR		AT_PTR
#define QTYPE_G			AT_G
#define QTYPE_MX		3
#define QTYPE_A_STR		"snsd"
#define QTYPE_PTR_STR		"ptr"
#define QTYPE_G_STR		"global"
#define QTYPE_MX_STR		"mx"

#define SNSD_PROTO_TCP		0
#define SNSD_PROTO_UDP		1
#define SNSD_PROTO_TCP_STR	"tcp"
#define SNSD_PROTO_UDP_STR	"udp"

#define SNSD_PROTO_DEFAULT	SNSD_PROTO_TCP
#define SNSD_SERVICE_DEFAULT	0

/* NK BIT */
#define NK_DNS			0
#define NK_NTK                  1
#define NK_INET                 2

#define TIME_SCALE		1000000.0
#define HELP_STR		"help"



char *QTYPE_STR_LIST[]={QTYPE_A_STR,QTYPE_PTR_STR,QTYPE_G_STR,QTYPE_MX_STR};
int QT_LEN=4;

#define QTFROMPREF(s)							\
({									\
 	int __n,__res=-1;						\
	for (__n=0;__n<QT_LEN;__n++) 					\
		if (!strncasecmp(s,QTYPE_STR_LIST[__n],strlen(s))) 	\
 			{__res=__n;break;}				\
	__res; })			
#define REALMFROMPREF(s)						\
({									\
	uint8_t __res=0;						\
	if (!strncasecmp(REALM_NTK_STR,s,strlen(s)))			\
		__res=REALM_NTK;					\
	else if (!strncasecmp(REALM_INT_STR,s,strlen(s)))		\
 		__res=REALM_INT; 					\
		__res; })	
#define PROTOFROMPREF(s)						\
({									\
 	uint8_t __res=-1;						\
	if (!strncasecmp(SNSD_PROTO_UDP_STR,s,strlen(s)))		\
		__res=SNSD_PROTO_UDP;					\
	else if (!strncasecmp(SNSD_PROTO_TCP_STR,s,strlen(s)))		\
 		__res=SNSD_PROTO_TCP; 					\
		__res; })	

		
			
typedef struct ntkresolv_opts {
	char		nsserver[MAX_HOSTNAME_LEN];
	int16_t		port;
	int8_t		silent;
	char		obj[NTKRESOLV_MAX_OBJ_LEN];
	uint16_t	id;
	uint8_t		hash;
	andns_pkt	*q;
} ntkresolv_opts;

#define NTKRESOLV_OPTS_SZ	sizeof(ntkresolv_opts)

#define QR_STR(ap)	((ap)->qr==0)?"QUERY":"ANSWER"
#define QTYPE_STR(ap)						\
({								\
 	char *__c;						\
 	switch((ap)->qtype) {					\
 		case AT_A:					\
			__c="Host2Ip";				\
			break;					\
 		case AT_PTR:					\
			__c="Ip2Host";				\
			break;					\
		case AT_G:					\
 			__c=" Global";				\
 			break;					\
		default:					\
			__c="Unknow";				\
 			break;					\
			}					\
		__c;})						
#define NK_STR(ap)						\
({								\
	char *__d;						\
	switch((ap)->nk) {					\
		case NK_DNS:					\
			__d="DNS";				\
			break;					\
		case NK_NTK:					\
			__d="Ntk";				\
			break;					\
		case NK_INET:					\
			__d="Inet";				\
			break;					\
		default:					\
			__d="UNKNOW";				\
 			break;					\
			}					\
 		__d;})						

#define RCODE_STR(ap)						\
({								\
 	char *__e;						\
	switch((ap)->rcode) {					\
		case ANDNS_RCODE_NOERR:				\
			__e="NoError";				\
			break;					\
		case ANDNS_RCODE_EINTRPRT:			\
			__e="InError";				\
			break;					\
		case ANDNS_RCODE_ESRVFAIL:			\
			__e="SrvFail";				\
			break;					\
		case ANDNS_RCODE_ENSDMN:			\
			__e="NoXHost";				\
			break;					\
		case ANDNS_RCODE_ENIMPL:			\
			__e="NotImpl";				\
			break;					\
		case ANDNS_RCODE_ERFSD:				\
			__e="Refused";				\
			break;					\
		default:					\
			__e="UNKNOW";				\
			break;					\
	}							\
	__e;})
#define IPV_STR(ap)						\
({								\
 	char *__f;						\
 	switch((ap)->ipv) {					\
		case ANDNS_IPV4:				\
 			__f="IPv4";				\
 			break;					\
		case ANDNS_IPV6:				\
 			__f="IPv6";				\
 			break;					\
		default:					\
			__f="UNKNOW";				\
			break;					\
	}							\
	__f;})
#define MAX_INT_STR	10
#define SERVICE_STR(ap)						\
({								\
 	char *__g;						\
 	char __t[MAX_INT_STR];					\
 	switch((ap)->qtype) {					\
		case AT_G:					\
 			__g="*";				\
 			break;					\
		case AT_PTR:					\
 			__g="None";				\
 			break;					\
		case AT_A:					\
 			snprintf(__t,MAX_INT_STR,"%d",		\
				ap->service);			\
 			__g=__t;				\
 			break;					\
		default:					\
			__g="UNKNOW";				\
			break;					\
	}							\
	__g;})
#define PROTO_STR(ap)						\
({								\
 	char *__h;						\
 	switch((ap)->qtype) {					\
		case AT_G:					\
 			__h="*";				\
 			break;					\
		case AT_PTR:					\
 			__h="None";				\
 			break;					\
		case AT_A:					\
 			if (!ap->service)			\
 				__h="None";			\
 			else					\
	 			__h=ap->p==SNSD_PROTO_TCP?	\
 				SNSD_PROTO_TCP_STR:		\
 				SNSD_PROTO_UDP_STR;		\
 			break;					\
		default:					\
			__h="UNKNOW";				\
			break;					\
	}							\
	__h;})
 	

#define GET_OPT_REALM	(globopts.realm==REALM_NTK)?"NTK":"INET"

/* CODE UTILS */
#define GOP             (globopts)
#define AMISILENT       (GOP.silent)
#define GQT             (GOP.q)

#define say             printf
#define bye             if (!AMISILENT) say("\tBye!\n");

#define COMPUTE_TIME    diff_time(time_start,time_stop)
#define time_report     if (!AMISILENT){gettimeofday(&time_stop,NULL);      \
                        say("Query time: %f seconds.\n"                     \
                                        ,COMPUTE_TIME);}

#define G_ALIGN(len)    GQT->qstlength=len;GQT->qstdata=(char*)  	    \
                                xmalloc(len+1);       		            \
                                if (!GQT->qstdata){say("Fatal malloc!\n");  \
                                        exit(1);}
#define G_SETQST_A(s)   G_ALIGN(strlen(s)+1);strcpy(GQT->qstdata,s);        \
                                GQT->qstlength=strlen(s);

#define NTK_RESOLV_HASH_STR(s,d)			        	    \
({									    \
 	int __i;							    \
 	for (__i=0;__i<ANDNS_HASH_H;__i++) 				    \
 		sprintf(d+2*__i,"%02x",((unsigned char*)(s))[__i]);	    \
	d[2*ANDNS_HASH_H]=0;})

#define NTK_RESOLV_STR_HASH(s,d)			        	    \
({									    \
 	int __i,__t;							    \
 	for (__i=0;__i<ANDNS_HASH_H;__i++) { 				    \
 		sscanf(s+2*__i,"%02x",&__t);				    \
		d[__i]=(unsigned char)(__t);}})

#define NTK_RESOLV_IP_SYMBOL	"~"
#define NTK_RESOLV_HNAME_SYMBOL	"-"
#define NTK_RESOLV_SYMBOL(apd)	(apd)->m&APD_IP?NTK_RESOLV_IP_SYMBOL:	\
					NTK_RESOLV_HNAME_SYMBOL

/* FUNCTIONS */

void version(void);
void usage(void);
void qt_usage(char *arg);
void realm_usage(char *arg);
void proto_usage(char *arg);
void service_and_proto_usage(char *arg);
double diff_time(struct timeval a,struct timeval b);
void opts_init(void);
void opts_set_silent(void);
void opts_set_port(char *arg);
void opts_set_ns(char *arg);
void opts_set_qt(char *arg);
void opts_set_realm(char *arg);
void opts_set_service_and_proto(char *arg);
void opts_set_proto(char *arg) ;
void opts_set_recursion(void);
void opts_set_hash(void) ;
void opts_set_compute_hash(void);
void opts_set_parsable_output(void);
void opts_set_question(char *arg);
void opts_finish(char *arg);
void print_headers();
void print_question();
void ip_bin_to_str(void *data,char *dst);
void answer_data_to_str(andns_pkt_data *apd,char *dst);
void print_answers();
void print_parsable_answers(void);
void print_results(void);
void do_command(void);
void ntkresolv_exit(int i);
void ntkresolv_safe_exit(int i);
int main(int argc, char **argv);

#endif /* NTK_RESOLV_H */
