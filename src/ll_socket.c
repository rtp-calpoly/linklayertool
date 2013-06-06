/*
 * @file ll_socket.c
 * @author Ricardo Tubío (rtpardavila[at]gmail.com)
 * @version 0.1
 *
 * @section LICENSE
 *
 * This file is part of netlevel-tool.
 * netlevel-tool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * netlevel-tool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with netlevel-tool.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ll_socket.h"

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// STRUCTURES MANAGEMENT
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

/* new_if_req */
ifreq_t* new_ifreq()
{
	ifreq_t* buffer = NULL;
	buffer = (ifreq_t *)malloc(LEN__IFREQ);
	return(buffer);
}

/* new_sockaddr_ll */
sockaddr_ll_t *new_sockaddr_ll()
{
	sockaddr_ll_t *buffer = NULL;
	buffer = (sockaddr_ll_t *)malloc(LEN__SOCKADDR_LL);
	memset(buffer, 0, LEN__SOCKADDR_LL);
	return(buffer);
}

/* new_packet_mreq */
packet_mreq_t *new_packet_mreq()
{
	packet_mreq_t *buffer = NULL;
	buffer = (packet_mreq_t *)malloc(LEN__PACKET_MREQ);
	memset (buffer, 0, LEN__PACKET_MREQ);
	return(buffer);
}

/* new_tpacket_req */
tpacket_req_t *new_tpacket_req()
{
	tpacket_req_t *buffer = NULL;
	buffer = (tpacket_req_t *)malloc(LEN__TPACKET_REQ);
	memset (buffer, 0, LEN__TPACKET_REQ);
	return(buffer);
}

/* new_ev_io_arg */
ev_io_arg_t *new_ev_io_arg()
{
	ev_io_arg_t *buffer = NULL;
	buffer = (ev_io_arg_t *)malloc(LEN__EV_IO_ARG);
	memset (buffer, 0, LEN__EV_IO_ARG);
	return(buffer);
}

/* init_ev_io_arg */
ev_io_arg_t *init_ev_io_arg(ll_socket_t *ll_socket)
{
	ev_io_arg_t *buffer = new_ev_io_arg();

	#ifdef KERNEL_RING
		buffer->rx_ring = ll_socket->rx_ring_buffer;
	#else
		buffer->rx_frame = ll_socket->rx_frame;
	#endif

	return(buffer);
}

/* init_tpacket_req */
tpacket_req_t *init_tpacket_req(const int frames_per_block, const int no_blocks)
{
	tpacket_req_t *t = new_tpacket_req();
  	t->tp_block_size = frames_per_block * getpagesize();
  	t->tp_block_nr = no_blocks;
  	t->tp_frame_size = getpagesize();
  	t->tp_frame_nr = frames_per_block * no_blocks;
  	return(t); 	
}

/* init_sockaddr_ll */
sockaddr_ll_t *init_sockaddr_ll(const ll_socket_t* ll_socket)
{

	sockaddr_ll_t *t = new_sockaddr_ll();
	
	t->sll_family = PF_PACKET;
	t->sll_ifindex = ll_socket->if_index;
	t->sll_protocol = htons(ll_socket->ll_sap);
  	t->sll_halen = ETH_ALEN;
  	memset(t->sll_addr, 0xff, ETH_ALEN);
  	
  	return(t);
  	
}

/* if_name_2_if_index */
int if_name_2_if_index(const int socket_fd, const char *if_name)
{

	int len_if_name = -1;

	if ( if_name == NULL )
		{ return(EX_NULL_PARAM); }
	
	len_if_name = strlen(if_name);
	
	if ( len_if_name == 0 )
		{ return(EX_EMPTY_PARAM); }
	if ( len_if_name > IF_NAMESIZE )
		{ return(EX_WRONG_PARAM); }

	ifreq_t *ifr = new_ifreq();
	strncpy(ifr->ifr_name, if_name, len_if_name);
	
	if ( ioctl(socket_fd, SIOCGIFINDEX, ifr) < 0 )
		{ handle_sys_error("Could not get interface index"); }

	return(ifr->ifr_ifindex);

}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// LL_SOCKET MANAGEMENT
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

/* new_ll_socket */
ll_socket_t *new_ll_socket()
{
	ll_socket_t *buffer = NULL;
	buffer = (ll_socket_t *)malloc(LEN__LL_SOCKET);
	memset (buffer, 0, LEN__LL_SOCKET);
	return(buffer);
}

/* init_ll_socket */
ll_socket_t *init_ll_socket(const char *ll_if_name, const int ll_sap)
{

	#ifdef KERNEL_RING
		int tx_socket_fd = -1, rx_socket_fd = -1;
	#else
		int socket_fd = -1;
	#endif
	int ll_if_index = -1;
	ll_socket_t *s = new_ll_socket();
	
	s->state = LL_SOCKET_STATE_UNDEF;

	// 1) create RAW socket(s)	
	#ifdef KERNEL_RING
		if ( ( tx_socket_fd = socket(PF_PACKET, SOCK_RAW, ll_sap) ) < 0 )
			{ handle_sys_error("Could not open TX socket"); }
		if ( ( rx_socket_fd = socket(PF_PACKET, SOCK_RAW, ll_sap) ) < 0 )
			{ handle_sys_error("Could not open RX socket"); }
	#else
		if ( ( socket_fd = socket(PF_PACKET, SOCK_RAW, ll_sap) ) < 0 )
			{ handle_sys_error("Could not open socket"); }
	#endif
	
	// 2) initialize fields
	#ifdef KERNEL_RING
		s->tx_socket_fd = tx_socket_fd;
		s->rx_socket_fd = rx_socket_fd;
	#else
		s->socket_fd = socket_fd;
		s->rx_frame = new_ieee8023_frame();
	#endif
	s->ll_sap = ll_sap;
	#ifdef KERNEL_RING
		log_app_msg("Socket created, TX_FD = %d, RX_FD = %d, ll_sap = %d\n",
						tx_socket_fd, rx_socket_fd, ll_sap);
	#else
		log_app_msg("Socket created, FD = %d, ll_sap = %d\n",
						socket_fd, ll_sap);
	#endif
	
	// 3) get interface index from interface name
	#ifdef KERNEL_RING
		int socket_fd = tx_socket_fd;
	#endif
	if ( ( ll_if_index = if_name_2_if_index(socket_fd, ll_if_name) ) < 0 )
	{
		handle_app_error(	"Could not get interface index, if_name = %s\n", 
							ll_if_name	);
	}
	
	strncpy(s->if_name, ll_if_name, strlen(ll_if_name));
	s->if_index = ll_if_index;
	
	log_app_msg("IF: name = %s, index = %d\n", ll_if_name, ll_if_index);
	
	// 4) initialize libevent
	if ( init_events(s) < 0 )
		{ handle_app_error("Could not initialize event manager!"); }

	// Ready is socket's final state
	s->state = LL_SOCKET_STATE_READY;

	return(s);
	
}

/* new_ll_socket */
ll_socket_t *open_ll_socket(const char* ll_if_name, const int ll_sap)
{

	// 1) create RAW socket
	ll_socket_t *ll_socket = init_ll_socket(ll_if_name, ll_sap);
	
	// 2) initialize rings for frames tx+rx
	#ifdef KERNEL_RING
		if ( init_rings(ll_socket) < 0 )
			{ handle_app_error("Could not initialize TX/RX rings.\n"); }
		log_app_msg("IO rings iniatialized.\n");
	#endif
	
	// 3) bind RAW socket	
	if ( bind_ll_socket(ll_socket) < 0 )
		{ handle_sys_error("Could not bind socket"); }
	log_app_msg("ll_socket bound, ll_sap = %d.\n", ll_socket->ll_sap);
	
	return(ll_socket);

}

/* bind_socket */
int bind_ll_socket(ll_socket_t *ll_socket)
{

	sockaddr_ll_t *sll = init_sockaddr_ll(ll_socket);
	
	#ifdef KERNEL_RING
		if ( bind(	ll_socket->tx_socket_fd,
					(struct sockaddr *)sll, LEN__SOCKADDR_LL)
				< 0 )
			{ handle_sys_error("Binding TX socket"); }
	
		if ( bind(	ll_socket->rx_socket_fd,
					(struct sockaddr *)sll, LEN__SOCKADDR_LL)
				< 0 )
			{ handle_sys_error("Binding RX socket"); }
	#else
		if ( bind(	ll_socket->socket_fd,
					(struct sockaddr *)sll, LEN__SOCKADDR_LL)
				< 0 )
			{ handle_sys_error("Binding socket"); }
	#endif
	
	return(EX_OK);

}

/* close_ll_socket */
int close_ll_socket(const ll_socket_t *ll_socket)
{

	int result = EX_OK;

	#ifdef KERNEL_RING
		if ( close_rings(ll_socket) < 0 )
		{
			log_sys_error("Error closing rings");
			result = EX_ERR;
		}
	#endif

	#ifdef KERNEL_RING
		if ( close(ll_socket->tx_socket_fd) < 0 )
		{
			log_sys_error("Closing TX socket");	
			result = EX_ERR;
		}

		if ( close(ll_socket->rx_socket_fd) < 0 )
		{
			log_sys_error("Closing RX socket");	
			result = EX_ERR;
		}
	#else
		if ( close(ll_socket->socket_fd) < 0 )
		{
			log_sys_error("Closing socket");	
			result = EX_ERR;
		}
	#endif

	if ( close_events(ll_socket) < 0 )
	{
		log_sys_error("Closing events manager");
		result = EX_ERR;
	}

	return(result);

}

/* set_sockaddr_ll */
int set_sockaddr_ll(ll_socket_t *ll_socket)
{

	#ifdef KERNEL_RING
		ll_socket->tx_ring_addr = init_sockaddr_ll(ll_socket);
		ll_socket->rx_ring_addr = init_sockaddr_ll(ll_socket);
	#else
		ll_socket->addr = init_sockaddr_ll(ll_socket);
	#endif
	
	return(EX_OK);
	
}

/* set_promiscuous_ll_socket */
int set_promiscuous_ll_socket(const ll_socket_t *ll_socket)
{

	packet_mreq_t *mr = new_packet_mreq();
	
	mr->mr_ifindex = ll_socket->if_index;
	mr->mr_type = PACKET_MR_PROMISC;
	
	#ifdef KERNEL_RING
	if ( setsockopt(	ll_socket->rx_socket_fd,
						SOL_PACKET, PACKET_ADD_MEMBERSHIP,
						mr, LEN__PACKET_MREQ	) < 0 )
	#else
	if ( setsockopt(	ll_socket->socket_fd,
						SOL_PACKET, PACKET_ADD_MEMBERSHIP,
						mr, LEN__PACKET_MREQ	) < 0 )
	#endif
		{ handle_sys_error("Could not set promiscuous mode"); }

	return(EX_OK);
	
}

#ifdef KERNEL_RING

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// KERNEL RING
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

/* init_rings */
int init_rings(ll_socket_t *ll_socket)
{
  	
	// 1) initialize rx ring
	if ( ( ll_socket->rx_ring_len
			= init_ring(	ll_socket->rx_socket_fd, PACKET_RX_RING,
							FRAMES_PER_BLOCK, NO_BLOCKS,
							&ll_socket->rx_ring_buffer	) )
				< 0 )
	{
  		log_app_msg("Could not set initialize RX ring.");
  		return(EX_ERR);
	}
	
	// 2) initialize tx ring
	if ( ( ll_socket->tx_ring_len
			= init_ring(	ll_socket->tx_socket_fd, PACKET_TX_RING,
							FRAMES_PER_BLOCK, NO_BLOCKS,
							&ll_socket->tx_ring_buffer	) )
				< 0 )
	{
  		log_app_msg("Could not set initialize TX ring.");
  		return(EX_ERR);
	}
	
  	// 3) set destination address for both kernel rings
  	if ( set_sockaddr_ll(ll_socket) < 0 )
  	{
  		log_app_msg("Could not set sockaddr_ll for TX/RX rings.");
  		return(EX_ERR);
  	}
  	
	return(EX_OK);

}

/* init_ring */
int init_ring(	const int socket_fd, const int type,
				const int frames_per_block, const int no_blocks,
				void **ring	)
{

	int ring_access_flags = PROT_READ | PROT_WRITE;
	tpacket_req_t *p = init_tpacket_req(frames_per_block, no_blocks);
	int ring_len = ( p->tp_block_size ) * ( p->tp_block_nr );
  	
  	// 1) export kernel mmap()ed memory
  	if ( setsockopt(socket_fd, SOL_PACKET, type, p, LEN__TPACKET_REQ) < 0 )
	{
		log_sys_error("Setting socket options for this ring");
		return(EX_ERR);
	}

	#ifdef TPACKET_V2
  		int val = TPACKET_V1;
  		if ( setsockopt(socket_fd, SOL_PACKET, PACKET_HDRLEN,
  							&val, sizeof(int)) < 0 )
			{ handle_sys_error("Setting TPACKET_V1 for this ring..."); }
	#endif
	
	// 2) open ring
  	if ( ( (*ring) = mmap(	NULL, ring_len, ring_access_flags, MAP_SHARED,
  							socket_fd, 0) ) == NULL )
	{
		log_sys_error("mmap()ing error");
		return(EX_ERR);
	}
	
	return(ring_len);
	
}

/* close_rings */
int close_rings(const ll_socket_t *ll_socket)
{

	int result = EX_OK;

	if ( munmap(ll_socket->tx_ring_buffer, ll_socket->tx_ring_len) < 0 )
	{
		log_sys_error("Closing TX ring buffer");
		result = EX_ERR;
	}

	if ( munmap(ll_socket->rx_ring_buffer, ll_socket->rx_ring_len) < 0 )
	{
		log_sys_error("Closing RX ring buffer");
		result = EX_ERR;
	}
	
	return(result);

}

#endif

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// LIBEV
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

/* init_events */
int init_events(ll_socket_t *ll_socket)
{

	ll_socket->loop = EV_DEFAULT;
	ev_io_arg_t *arg = init_ev_io_arg(ll_socket);
	ll_socket->rx_watcher = &arg->watcher;

#ifdef KERNEL_RING
	ev_io_init(	ll_socket->rx_watcher, cb_process_frame_rx,
				ll_socket->rx_socket_fd,
				EV_READ	);
#else
	ev_io_init(	ll_socket->rx_watcher, cb_process_frame_rx,
				ll_socket->socket_fd,
				EV_READ	);
#endif

	ev_io_start(ll_socket->loop, ll_socket->rx_watcher);

    return(EX_OK);

}

/* close_events */
int close_events(const ll_socket_t *ll_socket)
{

	int result = EX_OK;
	
	return(result);

}

/* cb_process_frame_rx */
void cb_process_frame_rx
	(struct ev_loop *loop, struct ev_io *watcher, int revents)
{

	if( EV_ERROR & revents )
	{
		log_sys_error("Invalid event");
		return;
	}

	log_app_msg(">>>>> Event FRAME_RX !!!\n");
	ev_io_arg_t *arg = (ev_io_arg_t *)watcher;

#ifdef KERNEL_RING
	if ( read_ieee8023_frame(arg->rx_ring, arg->rx_frame) < 0 )
#else
	if ( read_ieee8023_frame(watcher->fd, arg->rx_frame) < 0 )
#endif
	{
		log_app_msg("Could not read frame.");
		return;
	}

	print_ieee8023_frame(arg->rx_frame);

}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// DATA TX/RX INTERFACE
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

/* start_ll_socket */
int start_ll_socket(ll_socket_t *ll_socket)
{

	// 1) start event_loop event's reading
	log_app_msg("Starting ev_run_loop.\n");
	ev_run(ll_socket->loop, 0);
	log_app_msg("Done ev_run_loop.\n");
	ll_socket->state = LL_SOCKET_STATE_RUNNING;

	return(EX_OK);

}
