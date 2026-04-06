#include <asm-generic/types.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "bgp_attributes.h"


const __u8 FLAG_UNSET = 0;
const __u8 FLAG_EXTENDED = (__u8)1<<4;
const __u8 FLAG_PARTIAL = (__u8)1<<5;
const __u8 FLAG_TRANSITIVE = (__u8)1<<6;
const __u8 FLAG_OPTIONAL = (__u8)1<<7;

struct attrib {
    void *start_p;
    void *attr_data;
    void *attr_end;
    void *attr_len_p;
};

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

void dump_buffer(void *buffer,__u16 size)
{
    char ret_print[18];
    void *cur_pkt = buffer;
    printf ("%06x\t",0);
    fflush (stdout);
    for(int p = 0; p < size; p++)
    {
        if((p + 1) % 16 == 0)
            snprintf (ret_print,10,"\n%06x\t",p + 1);
        printf ("%02x%s",*(uint8_t *) (cur_pkt + p),
                ((p + 1) % 16 == 0)?ret_print:" ");
        fflush (stdout);
    }
    printf ("\n\n");
    fflush (stdout);
}

void *get_attr_len_ptr(struct bgp_header *hdr) {
    char *ptr = (void *)hdr;
    __u16 withdrawn_len = ntohs(*(__u16*)(hdr+1));
    if (withdrawn_len == 0) {
        return ptr+21;
    }
    return ptr+21+withdrawn_len;
}

void increment_lengths(struct bgp_header *hdr, const __u16 length) {
    __u16 *attr_len_p = get_attr_len_ptr(hdr);
    hdr->length = htons(ntohs(hdr->length)+length);
    *attr_len_p = htons(ntohs(*attr_len_p)+length);
}

struct bgp_header *construct_update_header(char *ptr) {
    struct bgp_header *hdr = (void *)ptr;
    memset(hdr->header, 0xFF, 16);
    hdr->length = htons(19);
    hdr->type = BGP_UPDATE;
    return hdr;
}

void add_attrib_hdr(struct bgp_header *hdr, __u8 flags, __u8 code) {
    char *ptr = (void *)hdr;
    ptr+=ntohs(hdr->length);
    ptr[0] = flags;
    ptr[1] = code;
    increment_lengths(hdr, 2);
}

char *bgp_find_attribute(struct bgp_header *hdr, __u8 code) {
    char *ptr = (void *)hdr;
    char *attr_len_p = NULL;
    __u16 withdrawn_len = *(__u16*)(ptr+19);
    if (withdrawn_len != 0)
        attr_len_p = (ptr+19+2+htons(withdrawn_len));
    else
        attr_len_p = ptr+19+2;
    __u16 attr_len = htons(*(__u16*)attr_len_p);
    ptr = attr_len_p+2;
    char *attr_end = attr_len_p+2+attr_len;
    while (ptr != attr_end) {
        if (ptr[1] == code)
            return ptr;
        if ((*(__u8*)ptr & FLAG_EXTENDED) != 0) {
            ptr += (4+ntohs(*(__u16*)&ptr[2]));
            continue;
        }
        ptr += (3+ptr[2]);
    }
    return NULL;
}

void add_attr_value(struct bgp_header *hdr, const void *data, const __u16 length) {
    char *ptr = (void *)hdr;
    ptr += ntohs(hdr->length);
    if (length == 0) {
        *(__u8*)ptr = 0;
        increment_lengths(hdr, 1);
        return;
    }
    if((*(__u8*)(ptr-2) & FLAG_EXTENDED) == FLAG_EXTENDED) {
        *(__u16*)ptr = htons(length);
        memcpy(ptr+2, data, length);
        increment_lengths(hdr, 2+length);
        return;
    }
    *(__u8*)ptr = (__u8)length;
    memcpy(ptr+1, data, length);
    increment_lengths(hdr, 1+length);
}

int add_origin_attribute(struct bgp_header *hdr, const __u8 value) {
    if (value != ORIGIN_IGP && value != ORIGIN_INCOMPLETE)
        return -1;
    add_attrib_hdr(hdr, FLAG_TRANSITIVE, ORIGIN_ATTRIBUTE);
    add_attr_value(hdr, &value, 1);
    return 0;
}

int add_nh_attribute(struct bgp_header *hdr, char *value) {
    __u32 address = 0;
    if (inet_pton(AF_INET, value, &address) != 1) {
        printf("Invalid address %s specified\n", value);
        return -1;
    }
    add_attrib_hdr(hdr, FLAG_TRANSITIVE, NEXTHOP_ATTRIBUTE);
    add_attr_value(hdr, &address, 4);
    return 0;
}

void add_local_pref_attribute(struct bgp_header *hdr, __u32 value) {
    value = htonl(value);
    add_attrib_hdr(hdr, FLAG_TRANSITIVE, LPREF_ATTRIBUTE);
    add_attr_value(hdr, &value, 4);
}

// Adds an empty AS Path - we deal with adding ASN's in a separate function
void add_as_path(struct bgp_header *hdr) {
    // For the purposes of this code we assume any asns are an AS Sequence
    add_attrib_hdr(hdr, FLAG_TRANSITIVE, AS_PATH_ATTRIBUTE);
    add_attr_value(hdr, NULL, 0);
}

int add_asn(struct bgp_header *hdr, __u32 asn) {
    char *ptr = bgp_find_attribute(hdr, AS_PATH_ATTRIBUTE);
    asn = htonl(asn);
    char *data_ptr = NULL;
    __u16 attr_len;
    if (!ptr)
        return -1;
    bool use_extended = false;
    if ((ptr[0] & FLAG_EXTENDED) == FLAG_EXTENDED)
        use_extended = true;
    if (use_extended) {
        attr_len = ntohs(*(__u16*)&ptr[2]);
        data_ptr = ptr+4;
    } else {
        attr_len = ptr[2];
        data_ptr = ptr+3;
    }
    __u16 remaining_length = ntohs(hdr->length)-(data_ptr-(char*)hdr);
    if (attr_len == 0) {
        // we need to add at least 6 bytes here
        memcpy(&data_ptr[6], data_ptr, remaining_length);
        memset(data_ptr, 0, 6);
        data_ptr[0] = AS_PATH_SEQUENCE;
        data_ptr[1] = 1;
        memcpy(&data_ptr[2], &asn, 4);
        increment_lengths(hdr, 6);
        if (use_extended) {
            *(__u16*)&ptr[2] = htons(6);
        } else {
            ptr[2] = 6;
        }
    } else {
        data_ptr[1]++;
        data_ptr+=2;
        memcpy(&data_ptr[4], data_ptr, remaining_length);
        memcpy(data_ptr, &asn, 4);
        increment_lengths(hdr, 4);
        if (use_extended) {
            *(__u16*)&ptr[2] = htons(attr_len+4);
        } else {
            ptr[2] = attr_len+4;
        }
    }
    return 0;
}

int add_route_target4(struct bgp_header *hdr, const char *target, __u16 color) {
    __u32 address = 0;
    if (inet_pton(AF_INET, target, &address) != 1) {
        printf("Invalid target IP address\n");
        return -1;
    }
    char rt[6] = {0};
    rt[0] = 1;
    rt[1] = 2;
    color = htons(color);
    memcpy(&rt[2], &address, 4);
    *(__u16*)&rt[6] = color;
    add_attrib_hdr(hdr, FLAG_TRANSITIVE|FLAG_OPTIONAL, EXTENDED_COMM_ATTRIBUTE);
    add_attr_value(hdr, rt, 8);
    return 0;
}

int main() {
    char update[4096] = {0}; // As per RFC4271 BGP updates cannot exceed 4096 bytes
    struct bgp_header *hdr = construct_update_header(update);
    // Add 4 bytes to the header length to cater for withdrawn length and attribute lengt
    hdr->length = htons(ntohs(hdr->length)+4);
    add_origin_attribute(hdr, ORIGIN_IGP);
    add_as_path(hdr);
    add_nh_attribute(hdr, "10.10.10.10");
    add_local_pref_attribute(hdr, 100);
    add_route_target4(hdr, "10.20.30.1", 0);
    add_asn(hdr, 65001);
    add_asn(hdr, 65002);
    dump_buffer(hdr, ntohs(hdr->length));
}

