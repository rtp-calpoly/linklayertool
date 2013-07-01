/*
 * @file ieee80211_frame.h
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

#ifndef IEEE80211_FRAME_H_
#define IEEE80211_FRAME_H_

#include "execution_codes.h"
#include "logger.h"
#include "ll_library/ll_frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <sys/time.h>

/***************************************************** IEEE 802.11 structures */

#define IEEE_80211_HLEN 		30		/*!< IEEE 802.11 header length (B). */
#define IEEE_80211_BLEN 		2312	/*!< IEEE 802.11 body length (B). */
#define IEEE_80211_FRAME_LEN	2342	/*!< IEEE 802.11 frame length (B). */

/*!
 * \struct ieee80211_header_frame_control
 * \brief Frame control field (2 B), composed of MAC service (1 B) and flags
 * 			(1 B).
 */
typedef struct ieee80211_header_frame_control
{

	uint8_t mac_service;				/*!< IEEE 802.11 MAC service (1 B). */
	uint8_t flags;						/*!< IEEE 802.11 flags (1 B). */

} ieee80211_header_frame_control_t;

#define LEN__IEEE_80211_FRAME_CONTROL sizeof(ieee80211_header_frame_control_t)

/*!
 *	\struct ieee80211_header
 *	\brief Structure for decoding the header of an IEEE 802.11 frame.
 */
typedef struct ieee80211_header
{

	ieee80211_header_frame_control_t
		frame_control;						/*!< Frame control field (2 B). */

	uint16_t duration_id;					/*!< Duration id field (2 B). */

	unsigned char bssid_address[ETH_ALEN];	/*!< BSSID MAC address. */
	unsigned char src_address[ETH_ALEN];	/*!< Source MAC address. */
	unsigned char dest_address[ETH_ALEN];	/*!< Destination MAC address. */

	uint16_t sequence_control;				/*!< Sequence control (2 B). */

	unsigned char dist_address[ETH_ALEN];	/*!< Distribution MAC address. */

	char data[IEEE_80211_BLEN];				/*!< Frame body (0 - 2312 B). */

} ieee80211_header_t ;

#define LEN__IEEE80211_HEADER sizeof(ieee80211_header_t)

/*!
 * \struct ieee80211_buffer
 * \brief Structure for decoding an IEEE 802.11 ethernet frame.
 */
typedef struct ieee80211_frame_buffer
{

	ieee80211_header_t header;	/*!< IEEE 802.11 header. */
	char data[ETH_DATA_LEN];	/*!< Data of the ethernet frame. */

} ieee80211_buffer_t;

#define LEN__IEEE80211_BUFFER sizeof(ieee80211_buffer_t)

/*!
 * \struct ieee80211_frame
 * \brief Structure for holding an IEEE 80211 frame and its associated
 * 			management information.
 */
typedef struct ieee80211_frame
{

	ll_frame_t info;			/*!< Info relative to frame management. */
	ieee80211_buffer_t buffer;	/*!< Buffer with frame contents. */

} ieee80211_frame_t;

#define LEN__IEEE80211_FRAME sizeof(ieee80211_frame_t)

/***************************************************** IEEE 802.11 functions */

/*!
	\brief Allocates memory for a ieee80211_buffer structure.
	\return A pointer to the newly allocated block of memory.
*/
ieee80211_frame_t *new_ieee80211_frame();

/*!
 * \brief Initializes an IEEE 802.11 frame with the given data.
 * \return A pointer to the initialized structure.
 */
ieee80211_frame_t *init_ieee80211_frame
	(	const uint8_t mac_service, const uint8_t flags,
		const uint16_t duration_id,
		const unsigned char *bssid,
		const unsigned char *h_source, const unsigned char *h_dest,
		const uint16_t sequence_control,
		const unsigned char *dist_address	);

/*!
	\brief Reads from a socket an ll_framebuffer.
	\param socket_fd The socket from where to read the frame.
	\return EX_OK if everything was correct; otherwise < 0.
 */
#ifdef KERNEL_RING
	int read_ieee80211_frame(const void *rx_ring, ieee80211_frame_t *rx_frame);
#else
	int read_ieee80211_frame(const int socket_fd, ieee80211_frame_t *rx_frame);
#endif

/*!
 * \brief Prints the data of the given IEEE 802.3 frame.
 * \param frame The frame whose data is to be printed out.
 * \return EX_OK if everything was correct; otherwise < 0.
 */
int print_ieee80211_frame(const ieee80211_frame_t *frame);

#endif /* IEEE80211_FRAME_H_ */
