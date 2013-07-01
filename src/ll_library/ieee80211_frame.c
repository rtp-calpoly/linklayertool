/*
 * @file ieee80211_frame.c
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

 #include "ieee80211_frame.h"

/* new_ieee80211_frame */
ieee80211_frame_t *new_ieee80211_frame()
{

	ieee80211_frame_t *buffer = NULL;
	buffer = (ieee80211_frame_t *)malloc(LEN__IEEE80211_FRAME);
	memset(buffer, 0, LEN__IEEE80211_FRAME);
	return(buffer);

}

/* init_ieee80211_frame */
ieee80211_frame_t *init_ieee80211_frame
	(	const uint8_t mac_service, const uint8_t flags,
		const uint16_t duration_id,
		const unsigned char *bssid,
		const unsigned char *h_source, const unsigned char *h_dest,
		const uint16_t sequence_control,
		const unsigned char *dist_address	)
{

	ieee80211_frame_t *f = new_ieee80211_frame();
	ieee80211_header_t *h = &f->buffer.header;

	if ( set_ll_frame(&f->info, TYPE_IEEE_80211, ETH_FRAME_LEN) < 0 )
		{ log_app_msg("Could not set info adequately!\n"); }

	h->frame_control.mac_service = mac_service;
	h->frame_control.flags = flags;

	h->duration_id = duration_id;

	memcpy(h->bssid_address, bssid, ETH_ALEN);
	memcpy(h->dest_address, h_dest, ETH_ALEN);
	memcpy(h->src_address, h_source, ETH_ALEN);

	h->sequence_control = sequence_control;

	memcpy(h->dist_address, dist_address, ETH_ALEN);

	return(f);

}

#ifdef KERNEL_RING

/* read_ieee80211_frame */
int read_ieee80211_frame(const void *rx_ring, ieee80211_frame_t *rx_frame)
{
		//struct tpacket_hdr *header = NULL;

		//header = (void *) rx_ring + (rxring_offset * getpagesize());

		log_app_msg("Unsupported mmap reading...\n");
		return(EX_ERR);
}

#else

/* read_ieee80211_frame */
int read_ieee80211_frame(const int socket_fd, ieee80211_frame_t *frame)
{

	int b_read = read(socket_fd, &frame->buffer, IEEE_80211_FRAME_LEN);

	if ( b_read < 0 )
	{
		log_sys_error("Could not read socket");
		return(EX_ERR);
	}
	if ( b_read < frame->info.frame_len )
	{
		log_app_msg("Read %d bytes, but %d bytes were requested.\n"
						, b_read, IEEE_80211_FRAME_LEN);
	}

	if ( set_ll_frame(&frame->info, TYPE_IEEE_80211, b_read) < 0 )
	{
		log_app_msg("Error setting ll_frame's info.\n");
	}

	return(EX_OK);

}

#endif

/* print_ieee80211_frame */
int print_ieee80211_frame(const ieee80211_frame_t *frame)
{

	if ( print_ll_frame(&frame->info) < 0 ) { return(EX_ERR); }

	log_app_msg("\t* header->frame_control.mac_service = %02X\n"
						, frame->buffer.header.frame_control.mac_service);
	log_app_msg("\t* header->frame_control.flags = %02X\n"
						, frame->buffer.header.frame_control.flags);
	log_app_msg("\t* header->duration_id = %d\n"
						, frame->buffer.header.duration_id);

	log_app_msg("\t* header->bssid = ");
		print_eth_address(frame->buffer.header.bssid_address);
		log_app_msg("\n");
	log_app_msg("\t* header->src = ");
		print_eth_address(frame->buffer.header.src_address);
		log_app_msg("\n");
	log_app_msg("\t* header->dest = ");
		print_eth_address(frame->buffer.header.dest_address);
		log_app_msg("\n");

	log_app_msg("\t* header->sequence_control = %d\n"
						, frame->buffer.header.sequence_control);

	log_app_msg("\t* header->dist = ");
		print_eth_address(frame->buffer.header.dist_address);
		log_app_msg("\n");

	int data_len = frame->info.frame_len - IEEE_80211_HLEN;
	log_app_msg("\t* data[%d] = ", data_len);
	if ( print_hex_data((char *)&frame->buffer.data, data_len) < 0 )
		{ log_app_msg("\n"); return(EX_ERR); }
	log_app_msg("\n");

	return(EX_OK);

}
