#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <dirent.h>
#include "getaddrinfodnstest.c"

int
isValidIpv6Address (char *ipAddress)
{
  struct sockaddr_in6 sa;
  int result = inet_pton (AF_INET6, ipAddress, &(sa.sin6_addr));
  return result;
}

int
isValidIpv4Address (char *ipAddress)
{
  struct sockaddr_in sa;
  int result = inet_pton (AF_INET, ipAddress, &(sa.sin_addr));
  if (result == 0)
    {
      if (isValidIpv6Address (ipAddress) == 1)
	return AF_INET6;
      else
	return 0;
    }
  if (result == 1)
    return AF_INET;
  else
    return result;
}

/* Forwards packets to this IP through the inet 
 * iptables forwarding rule. */
void
inetipForwarding (char *ipAddress, int family)
{
  return;
}

/* Forwards packets to this IP through the ntk 
 * iptables forwarding rule. */
void
ntkipForwarding (char *ipAddress, int family)
{
  return;
}

/* Resolves the ntk domain name in ANDNA, 
 * Forwarding the originally desired packets
 * through the ntk iptables forwarding rule. */
void
ntkDNSResolution (char *domain)
{
  return;
}

/* Resolves the inet domain name via the commented out name servers
 * in /etc/resolv.conf, Forwarding the dns query packets
 * through the inet iptables forwarding rule.
 * Then, Forwards the originally desired packets
 * through the inet iptables forwarding rule. */
void
inetDNSResolution (char *domain)
{
  printf ("Inet Domain name %s resolves to:\n", domain);
  getaddrinfodnsresolution (domain);
  return;
}

void
inet_mode (char *domain)
{

  printf ("inet_mode: %s\n", domain);

  char *ret;
  char *ret1;
  char new_domain[MAXNAMLEN];
  int rt_value;

  strcpy (new_domain, domain);

  ret = strstr (new_domain, ".ntk");

  if (ret != NULL)
    {
      printf ("inet_mode .ntk\n");
      goto inet_mode_ntk_rslv;
    }

  ret = strstr (new_domain, ".inet");
  ret1 = strstr (new_domain, ".inet");

  if (ret1 != NULL)
    {
      new_domain[strlen (new_domain) - 5] = '\0';
      printf ("inet_mode abbrevate: %s\n", new_domain);
    }

  if (ret == NULL || ret1 != NULL)
    {
      rt_value = isValidIpv4Address (new_domain);
      if (rt_value == AF_INET)
	inetipForwarding (new_domain, AF_INET);
      if (rt_value == AF_INET6)
	inetipForwarding (new_domain, AF_INET6);
      if (rt_value == 0)
	inetDNSResolution (new_domain);
      printf ("inet_mode normal\n");
      return;
    }

  ret = strstr (new_domain, ".ntk");

  if (ret != NULL)
    {
    inet_mode_ntk_rslv:
      new_domain[strlen (new_domain) - 4] = '\0';
      rt_value = isValidIpv4Address (new_domain);
      if (rt_value == AF_INET)
	ntkipForwarding (new_domain, AF_INET);
      if (rt_value == AF_INET6)
	ntkipForwarding (new_domain, AF_INET6);
      if (rt_value == 0)
	ntkDNSResolution (new_domain);
      printf ("inet_mode abnormal\n");
      return;
    }

  return;
  
}

void
ntk_mode (char *domain)
{

  printf ("ntk_mode: %s\n", domain);

  char *ret;
  char *ret1;
  char new_domain[MAXNAMLEN];
  int rt_value;

  strcpy (new_domain, domain);

  ret = strstr (new_domain, ".inet");

  if (ret != NULL)
    {
      printf ("ntk_mode .inet\n");
      goto ntk_mode_inet_rslv;
    }

  ret = strstr (new_domain, ".ntk");
  ret1 = strstr (new_domain, ".ntk");

  if (ret1 != NULL)
    {
      new_domain[strlen (new_domain) - 4] = '\0';
      printf ("ntk_mode abbrevate: %s\n", new_domain);
    }

  if (ret == NULL || ret1 != NULL)
    {
      rt_value = isValidIpv4Address (new_domain);
      if (rt_value == AF_INET)
	ntkipForwarding (new_domain, AF_INET);
      if (rt_value == AF_INET6)
	ntkipForwarding (new_domain, AF_INET6);
      if (rt_value == 0)
	ntkDNSResolution (new_domain);
      printf ("ntk_mode normal\n");
    }

  ret = strstr (new_domain, ".inet");

  if (ret != NULL)
    {
    ntk_mode_inet_rslv:
      new_domain[strlen (new_domain) - 5] = '\0';
      rt_value = isValidIpv4Address (new_domain);
      if (rt_value == AF_INET)
	inetipForwarding (new_domain, AF_INET);
      if (rt_value == AF_INET6)
	inetipForwarding (new_domain, AF_INET6);
      if (rt_value == 0)
	inetDNSResolution (new_domain);
      printf ("ntk_mode abnormal\n");
    }

}

/*void
domain_ip_processing (char *domain)
{
  char *ret;
  char new_domain[MAXNAMLEN];
  int rt_value;
  int i;
  ret = strstr (domain, ".inet");
  strcpy (new_domain, domain);
  if (ret != NULL)
    {
      new_domain[strlen (new_domain) - 6] = '\0';
      rt_value = isValidIpv4Address (new_domain);
      if (rt_value == AF_INET)
	inetipForwarding (new_domain, AF_INET);
      if (rt_value == AF_INET6)
	inetipForwarding (new_domain, AF_INET6);
      if (rt_value == 0)
	inetDNSResolution (new_domain);

      printf ("This domain/ip address is an inet domain/ip address. %d\n",
	      rt_value);

    }

  ret = strstr (domain, ".ntk");
  if (ret != NULL)
    {
      new_domain[strlen (new_domain) - 5] = '\0';
      rt_value = isValidIpv4Address (new_domain);
      if (rt_value == AF_INET)
	ntkipForwarding (new_domain, AF_INET);
      if (rt_value == AF_INET6)
	ntkipForwarding (new_domain, AF_INET6);
      if (rt_value == 0)
	ntkDNSResolution (new_domain);

      printf ("This domain/ip address is an ntk domain/ip address. %d\n",
	      rt_value);
    }

  printf ("Domain/IP: %s %s\n", new_domain, domain);

}

int
main (void)
{
  for (;;)
    {
      char *request = (char *) malloc (100);
      printf ("\n> ");
      fgets (request, 100, stdin);
      if (strcmp (request, "quit\n") == 0 || strcmp (request, "exit\n") == 0)
	exit (0);
      fflush (stdin);
      *strrchr(request, '\n') = '\0';
      inet_mode (request);
      free (request);
    }

  return 0;
}*/
