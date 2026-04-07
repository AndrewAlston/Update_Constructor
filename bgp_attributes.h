//
// Created by andrew on 3/25/26.
//

#ifndef BGP_ATTRIBUTES_H
#define BGP_ATTRIBUTES_H

/** @enum BGP_TYPES
 * @brief Enumeration for BGP packet types
 */
enum BGP_TYPES {
    BGP_OPEN = 1, /**< Code point for BGP Open Packets */
    BGP_UPDATE = 2, /**< Code point for BGP Update packets */
    BGP_NOTIFICATION = 3, /**< Code point for BGP Notification packets */
    BGP_KEEPALIVE = 4 /**< Code point for BGP Keepalive packets */
};

/** @def ORIGIN_ATTRIBUTE
 * @brief The code point for ORIGIN attribute
 */
#define ORIGIN_ATTRIBUTE 1

/** @def AS_PATH_ATTRIBUTE
 * @brief The code point for AS Path attribute
 */
#define AS_PATH_ATTRIBUTE 2

/** @def NEXTHOP_ATTRIBUTE
 * @brief The code point for Next Hop attribute
 */
#define NEXTHOP_ATTRIBUTE 3

/** @def MED_ATTRIBUTE
 * @brief The code point for the multi-exit discriminator attribute
 */
#define MED_ATTRIBUTE 4

/** @def LPREF_ATTRIBUTE
 * @brief The code point for the local preference attribute
 */
#define LPREF_ATTRIBUTE 5

/** @def ATOMIC_AGGREGATE_ATTRIBUTE
 * @brief Thec ode point for the atomic aggregate attribute
 */
#define ATOMIC_AGGREGATE_ATTRIBUTE 6

/** @def AGGREGATOR_ATTRIBUTE
 * @brief The code point for the aggregator attribute
 */
#define AGGREGATOR_ATTRIBUTE 7

/** @def COMMUNITY_ATTRIBUTE
 * @brief The code point for the BGP standard communities attribute
 */
#define COMMUNITY_ATTRIBUTE 8

/** @def MP_BGP_ATTRIBUTE
 * @brief The code point for the multi-protocol BGP attribute
 */
#define MP_BGP_ATTRIBUTE 14

/** @def MP_BGP_WITHDRAW_ATTRIBUTE
 * @brief The code point for the multi-protocol BGP withdrawl attribute
 */
#define MP_BGP_WITHDRAW_ATTRIBUTE 15

/** @def EXTENDED_COMM_ATTRIBUTE 16
 * @brief The code point for extended community attributes
 */
#define EXTENDED_COMM_ATTRIBUTE 16

/** @def OTC_ATTRIBUTE
 * @brief The code point for the Only-To-Customer attribute
 */
#define OTC_ATTRIBUTE 35

/** @def EXPERIMENTAL_ATTRIBUTE
 * @brief Code point for experimental attributes that will be silently discarded
 */
#define EXPERIMENTAL_ATTRIBUTE 255

/** @def ORIGIN_IGP
 * @brief NLRI is interior to originating ASN
 */
#define ORIGIN_IGP 0

/** @def ORIGIN_EGP
 * @brief NLRI Learnt via EGP (deprecated)
 */
#define ORIGIN_EGP 1

/** @def ORIGIN_INCOMPLETE
 * @brief NLRI learnt via other means
 */
#define ORIGIN_INCOMPLETE 2

/** @def AS_PATH_SET
 * @brief Represents an AS PATH Set (RFC4271, Section4.3)
 */
#define AS_PATH_SET 1

/** @def AS_PATH_SET
 * @brief Represents an AS PATH Sequence (RFC4271, Section 4.3)
 */
#define AS_PATH_SEQUENCE 2

/** @struct attrib_code_flag
 * @brief Structure used for quick parsing of the first 2 bytes of a BGP attribute in an update packet
 */
struct attrib_code_flag {
 union {
  __u8 flags; /**< Bitwise flags related to the received attribute */
  struct {
   __u8 r1 :1; /**< Reserved bit - should always be unset */
   __u8 r2 :1; /**< Reserved bit - should always be unset */
   __u8 r3 :1; /**< Reserved bit - should always be unset */
   __u8 r4 :1; /**< Reserved bit - should always be unset */
   __u8 extended :1; /**< If set the attribute has an extended (16 bit) length */
   __u8 partial :1; /**< If set this is a partial attribute and the remainder of the attribute will be in next update */
   __u8 transitive :1; /**< If set this attribute is transitive and should be carried forward when onward announcing */
   __u8 optional :1; /**< If set this attribute is optional and may or may not be processed / forwarded */
  }; /**< Bitwise structure for the flags */
 }; /**< Anonymous union for flags processing */
 __u8 code; /**< The attribute code point */
};

/** @struct bgp_as_path
 * @brief Structure used for parsing / saving BGP AS Path attributes
 */
struct bgp_as_path {
 __u8 type; /**< The type of BGP AS Path, if 1, this is an AS Sequence, if 2 this is an AS Set */
 __u8 length; /**< The number of ASN's in this path */
 __u32 *asns; /**< Array of 32 bit ASN's in this path */
} __attribute__((__packed__));

/** @struct mp_bgp_header
 * @brief Overlay structure for processing MP_BGP attributes (Attribute 15)
 */
struct mp_bgp_header {
 __u16 afi; /**< Address family number */
 __u8 safi; /**< Sub address family number */
 __u8 nh_len; /**< Next hop length */
} __attribute__((__packed__));

/** @struct bgp_path_prefix
 * @brief Structure used for holding individual IPv4 prefixes received from update messages
 */
struct bgp_path_prefix {
 __u32 path_id; /**< Path ID (if add_path is enabled) */
 __u32 address; /**< The network address of the received prefix */
 __u8 cidr; /**< The bit depth of the prefix (CIDR Mask) */
 bool labeled; /**< If true this is a labeled prefix */
 __u32 *label_stack; /**< The label stack associated with this prefix */
 __u8 n_labels;
 struct bgp_attributes *attributes; /**< Pointer to an attribute structure for received attributes */
};

/** @struct bgp_path_prefix6
 * @brief Structure used for holding individual IPv6 prefixes received from update messages
 */
struct bgp_path_prefix6 {
 __u32 path_id; /**< Path ID (if add_path is enabled */
 __u8 prefix[16]; /**< The received prefix */
 __u8 cidr; /**< Bit depth of the received prefix (CIDR mask) */
 bool labeled; /**< If true this is a labeled prefix */
 __u32 *label_stack; /**< The label stack associated with this prefix */
 __u8 n_labels;
 struct bgp_attributes *attributes; /**< Pointer to an attribute structure for received attributes */
};

#endif
