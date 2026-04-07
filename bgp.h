//
// Created by andrew on 3/25/26.
//

#ifndef BGP_H
#define BGP_H

/** @struct bgp_header
 * @brief Structure to overlay over a buffer to extract a BGP header
 */
struct bgp_header {
    union {
        unsigned char header[16]; /**< BGP Header first 16 bytes (should always be 0xFF per byte */
        __u64 head[2]; /**< Overlay of first 16 bytes to two __u64's */
    }; /**< Anonymous union covering the first 16 bytes of the header */
    __u16 length; /**< BGP Header length (Network Byte Order */
    __u8 type; /**< BGP Packet type */
} __attribute__((__packed__));

#endif
