/* 
 * File:   netsplit.h
 * Author: missvaleska
 *
 * Created on November 6, 2014, 6:44 PM
 */

#ifndef NETSPLIT_H
#define	NETSPLIT_H

#include "netsplit.c"

#ifdef	__cplusplus
extern "C" {
#endif

int
isValidIpv6Address (char *ipAddress);

int
isValidIpv4Address (char *ipAddress);

/* Forwards packets to this IP through the inet 
 * iptables forwarding rule. */
void
inetipForwarding (char *ipAddress, int family);

/* Forwards packets to this IP through the ntk 
 * iptables forwarding rule. */
void
ntkipForwarding (char *ipAddress, int family);

/* Resolves the ntk domain name in ANDNA, 
 * Forwarding the originally desired packets
 * through the ntk iptables forwarding rule. */
void
ntkDNSResolution (char *domain);

/* Resolves the inet domain name via the commented out name servers
 * in /etc/resolv.conf, Forwarding the dns query packets
 * through the inet iptables forwarding rule.
 * Then, Forwards the originally desired packets
 * through the inet iptables forwarding rule. */
void
inetDNSResolution (char *domain);

void
inet_mode (char *domain);

void
ntk_mode (char *domain);

#ifdef	__cplusplus
}
#endif

#endif	/* NETSPLIT_H */

