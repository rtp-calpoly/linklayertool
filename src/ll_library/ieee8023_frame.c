/*
 * @file ll_frame.c
 * @author Ricardo Tubío (rtpardavila[at]gmail.com)
 * @version 0.1
 *
 * @section LICENSE
 *
 * This file is part of linklayertool.
 * linklayertool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * linklayertool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with linklayertool.  If not, see <http://www.gnu.org/licenses/>.
 */
 
 #include "ieee8023_frame.h"

/*!< Ethernet broadcast address. */
const unsigned char ETH_ADDR_BROADCAST[ETH_ALEN]
                                    = { 0xFF, 0xFF, 0XFF, 0xFF, 0xFF, 0xFF };

/* new_ethhdr */
struct ethhdr *new_ethhdr()
{

	struct ethhdr *buffer = NULL;
	buffer = (struct ethhdr *)malloc(ETH_FRAME_LEN);
	memset(buffer, 0, ETH_FRAME_LEN);
	return(buffer);

}

/* new_ieee8023_frame */
ieee8023_frame_t *new_ieee8023_frame()
{

	ieee8023_frame_t *buffer = NULL;
	buffer = (ieee8023_frame_t *)malloc(ETH_FRAME_LEN);
	memset(buffer, 0, ETH_FRAME_LEN);
	buffer->frame_len = ETH_FRAME_LEN;

	if ( gettimeofday(&buffer->timestamp, NULL) < 0 )
		{ log_sys_error("Cannot get timestamp"); }

	return(buffer);

}

/* read_ieee8023_frame */
#ifdef KERNEL_RING

int read_ieee8023_frame(const void *rx_ring, ieee8023_frame_t *rx_frame)
{
		//struct tpacket_hdr *header = NULL;

		//header = (void *) rx_ring + (rxring_offset * getpagesize());

		log_app_msg("Unsupported mmap reading...\n");
		return(EX_ERR);
}

#else

int read_ieee8023_frame(const int socket_fd, ieee8023_frame_t *rx_frame)
{

	int b_read = read(socket_fd, (void *)&rx_frame->frame, ETH_FRAME_LEN);

	if ( b_read < 0 )
	{
		log_sys_error("Could not read socket");
		return(EX_ERR);
	}
	if ( b_read < ETH_ZLEN )
	{
		log_app_msg("Read %d bytes < IEEE 802.3 min %d\n", b_read, ETH_ZLEN);
		return(EX_OK);
	}

	rx_frame->frame_len = b_read;
	return(EX_OK);

}

#endif

/* print_ieee8023_frame */
int print_ieee8023_frame(const ieee8023_frame_t *frame)
{

	log_app_msg(">>>>> IEEE 802.3 frame:\n");
	log_app_msg("\t* timestamp = %lu\n", get_timestamp_usecs(frame));
	log_app_msg("\t* header->dst = ");
		print_eth_address(frame->frame.header.h_dest);
		log_app_msg("\n");
	log_app_msg("\t* header->src = ");
		print_eth_address(frame->frame.header.h_source);
		log_app_msg("\n");
	log_app_msg("\t* header->sap = %02X\n", frame->frame.header.h_proto);
	log_app_msg("\t* header->data[%d] = ", frame->frame_len - ETH_HLEN);
		if ( print_eth_data(frame) < 0 )
			{ return(EX_ERR); }
		log_app_msg("\n");

	return(EX_OK);

}

/* print_eth_address */
void print_eth_address(const unsigned char *eth_address)
{

	printf("%02X:%02X:%02X:%02X:%02X:%02X",
  			(unsigned char) eth_address[0],
  			(unsigned char) eth_address[1],
  			(unsigned char) eth_address[2],
  			(unsigned char) eth_address[3],
  			(unsigned char) eth_address[4],
  			(unsigned char) eth_address[5]);

}

/* print_eth_data */
int print_eth_data(const ieee8023_frame_t *frame)
{

	int data_len = frame->frame_len - ETH_HLEN;
	int last_byte = data_len - 1;

	if ( data_len < 0 )
		{ return(EX_WRONG_PARAM); }

	for ( int i = 0; i < data_len; i++ )
	{
		if ( ( i % BYTES_PER_LINE ) == 0 )
			{ log_app_msg("\n\t\t\t"); }

		log_app_msg("%02X", 0xFF & (unsigned int)frame->frame.data[i]);
		if ( i < last_byte ) { log_app_msg(":"); }
	}

	return(EX_OK);

}

/* get_timestamp_usecs */
uint64_t get_timestamp_usecs(const ieee8023_frame_t *frame)
{
    return frame->timestamp.tv_sec * (uint64_t) 1000000
    				+ frame->timestamp.tv_usec;
}
