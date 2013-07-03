/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x11
#define MY_DEST_MAC2	0x22
#define MY_DEST_MAC3	0x33
#define MY_DEST_MAC4	0x44
#define MY_DEST_MAC5	0x55

#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024

#define USE_WRITE 1
#define GN_ETHTYPE 0x0707

/*!< Ethernet broadcast address. */
const unsigned char ETH_ADDR_BROADCAST[ETH_ALEN]
                                    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/*!< Ethernet NULL address. */
const unsigned char ETH_ADDR_NULL[ETH_ALEN]
                                    = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
/*!< Ethernet FAKE address. */
const unsigned char ETH_ADDR_FAKE[ETH_ALEN]
                                    = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
/*!< Ethernet SISCOGA-1-APU address. */
const unsigned char ETH_ADDR_S1A[ETH_ALEN]
                                    = { 0x00, 0x04, 0x5F, 0x03, 0xED, 0xCA };

int main(int argc, char *argv[])
{

	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	char ifName[IFNAMSIZ];

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	memcpy(eh->ether_shost, &(if_mac.ifr_hwaddr.sa_data), ETH_ALEN);
	memcpy(eh->ether_dhost, ETH_ADDR_S1A, ETH_ALEN);
	/* Ethertype field */
	eh->ether_type = htons(GN_ETHTYPE);

	tx_len += sizeof(struct ether_header);

	/* Packet data */
	sendbuf[tx_len++] = 0xde;
	sendbuf[tx_len++] = 0xad;
	sendbuf[tx_len++] = 0xbe;
	sendbuf[tx_len++] = 0xef;

	/* Send packet */
	int b_written = 0;
	struct sockaddr_ll socket_address;
	socket_address.sll_family = PF_PACKET;
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	//socket_address.sll_protocol = htons(ETH_P_LOOP);

#ifndef USE_WRITE
	socket_address.sll_halen = ETH_ALEN;
#endif

#ifdef USE_WRITE

	if (	bind(sockfd, (struct sockaddr*)&socket_address,
							sizeof(struct sockaddr_ll)) < 0		)
	{
	    perror("Could not bind socket...");
		fprintf(stderr, "ERRNO = %d\n", errno);
	    exit(-1);
	}

	if ( ( b_written = write(sockfd, sendbuf, tx_len) ) < 0 )

#else

	if ( ( b_written = sendto(	sockfd,
								sendbuf, tx_len, 0,
								(struct sockaddr*)&socket_address,
								sizeof(struct sockaddr_ll))	) < 0	)

#endif

	{
		perror("Could not write socket...");
		fprintf(stderr, "ERRNO = %d\n", errno);
		exit(-1);
	}
	printf("Packet sent!, Bytes written = %d\n", b_written);

	return 0;
}
