#include <asm-generic/types.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "bgp.h"
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

#ifndef IPV4_AFI
#define IPV4_AFI 1
#endif

#ifndef IPV6_AFI
#define IPV6_AFI 2
#endif

#ifndef SR_POLICY_SAFI
#define SR_POLICY_SAFI 73
#endif

#define TUNNEL_ENCAP_ATTRIBUTE 23

struct sr_preference_tlv {
    __u8 type;
    __u8 length;
    __u8 flags;
    __u8 reserved;
    __u32 preference;
} __attribute__((__packed__));

struct sr_binding_tlv {
    __u8 type;
    __u8 length;
    __u8 flags;
    __u8 reserved;
    __u32 sid;
} __attribute__((__packed__));

struct sr_priority_tlv {
    __u8 type;
    __u8 length;
    __u8 priority;
    __u8 reserved;
} __attribute__((__packed__));

struct sr_weight_tlv {
    __u8 type;
    __u8 length;
    __u8 flags;
    __u8 reserved;
    __u32 weight;
};
struct sr_segment_list {
    __u8 type;
    __u16 length;
    __u8 reserved;
} __attribute__((__packed__));;

struct sr_sid_type_a {
    __u8 type;
    __u8 length;
    __u8 flags;
    __u8 reserved;
    __u32 label;
};
struct tunnel_encap_sr_policy {
    __u16 type;
    __u16 type_len;
    struct sr_preference_tlv preference;
    struct sr_binding_tlv binding;
    struct sr_priority_tlv priority;
    struct sr_segment_list segments;
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
    const char *attr_end = attr_len_p+2+attr_len;
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

char *bgp_find_mp_afi_safi(struct bgp_header *hdr, const __u16 afi, const __u8 safi) {
    char *ptr = (void *)hdr;
    char *attr_len_p = NULL;
    __u16 withdrawn_len = *(__u16*)(ptr+19);
    if (withdrawn_len != 0)
        attr_len_p = (ptr+19+2+htons(withdrawn_len));
    else
        attr_len_p = ptr+21;
    ptr = attr_len_p+2;
    __u16 attr_len = ntohs(*(__u16*)attr_len_p);
    const char *attr_end = attr_len_p+2+attr_len;
    while (ptr != attr_end) {
        if (ptr[1] == MP_BGP_ATTRIBUTE) {
            if ((ptr[0] & FLAG_EXTENDED) == FLAG_EXTENDED) {
                if (*(__u16*)&ptr[4] == htons(afi) && ptr[6] == safi) {
                    return ptr;
                }
            }
            if (*(__u16*)&ptr[3] == htons(afi) && ptr[5] == safi) {
                return ptr;
            }
        }
        if ((ptr[0] & FLAG_EXTENDED) == FLAG_EXTENDED) {
            ptr+= (4+ntohs(*(__u16*)&ptr[2]));
            continue;
        }
        ptr+=3+ptr[2];
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
        if (remaining_length > 0) {
            memcpy(&data_ptr[6], data_ptr, remaining_length);
            memset(data_ptr, 0, 6);
        }
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

int add_mp_bgp_nlri(struct bgp_header *hdr, const __u16 afi, const __u8 safi, const char *nlri, const __u16 nlri_len) {
    char *ptr = bgp_find_mp_afi_safi(hdr, afi, safi);
    char *data_ptr = ptr;
    if (!ptr) {
        printf("Failed locating MP BGP Attribute with AFI %u and SAFI %u\n", afi, safi);
        return -1;
    }
    bool use_extended = false;
    __u16 attr_len;
    if ((ptr[0] & FLAG_EXTENDED) == FLAG_EXTENDED) {
        attr_len = htons(*(__u16*)&ptr[2]);
        use_extended = true;
        data_ptr = ptr+attr_len+4;
    } else {
        attr_len = ptr[2];
        data_ptr = ptr+attr_len+3;
    }
    __u16 remaining_length = ntohs(hdr->length)-(data_ptr-(char *)hdr);
    if (remaining_length > 0) {
        memcpy(&data_ptr[nlri_len], data_ptr, nlri_len);
        memset(data_ptr, 0, nlri_len);
    }
    memcpy(data_ptr, nlri, nlri_len);
    if (use_extended) {
        *(__u16*)&ptr[2] = htons(attr_len+nlri_len);
        increment_lengths(hdr, nlri_len);
        return 0;
    }
    ptr[2] = attr_len+nlri_len;
    increment_lengths(hdr, nlri_len);
    return 0;
}

int add_sr_policy_nlri(struct bgp_header *hdr, const __u16 afi, const __u32 distinguisher,
    const __u32 color, const char *endpoint) {
    char *ptr = bgp_find_mp_afi_safi(hdr, afi, SR_POLICY_SAFI);
    if (!ptr) {
        printf("Failed locating MP BGP AFI/SAFI %u/%u\n", afi, SR_POLICY_SAFI);
        return -1;
    }
    if (afi == IPV4_AFI) {
        char buf[13] = {0};
        buf[0] = 96;
        *(__u32*)&buf[1] = htonl(distinguisher);
        *(__u32*)&buf[5] = htonl(color);
        __u32 *address = (__u32*)&buf[9];
        if (inet_pton(AF_INET, endpoint, address) != 1)
            return -1;
        add_mp_bgp_nlri(hdr, afi, SR_POLICY_SAFI, buf, 13);
        return 0;
    }
    if (afi == IPV6_AFI) {
        char buf[25] = {0};
        buf[0] = 192;
        *(__u32*)&buf[1] = htonl(distinguisher);
        *(__u32*)&buf[5] = htonl(color);
        if (inet_pton(AF_INET6, endpoint, &buf[9]) != 1)
            return -1;
        add_mp_bgp_nlri(hdr, afi, SR_POLICY_SAFI, buf, 25);
        return 0;
    }
    return -1;
}

int add_mp_bgp(struct bgp_header *hdr, __u16 afi, const __u8 safi, const char *next_hop) {
    if (afi != IPV4_AFI && afi != IPV6_AFI) {
        printf("AFI was %u, expected %u or %u\n", afi, IPV4_AFI, IPV6_AFI);
        return -1;
    }
    char next_hop6[16];
    __u32 next_hop4;
    if (afi == IPV4_AFI) {
        if (inet_pton(AF_INET, next_hop, &next_hop4) != 1) {
            return -1;
        }
    } else {
        if (inet_pton(AF_INET6, next_hop, next_hop6) != 1)
            return -1;
    }
    add_attrib_hdr(hdr, FLAG_OPTIONAL, MP_BGP_ATTRIBUTE);
    char value[128] = {0};
    *(__u16*)&value[0] = htons(afi);
    value[2] = safi;
    if (afi == IPV4_AFI) {
        printf("Adding for IPv4 AFI\n");
        value[3] = 4;
        memcpy(&value[4], &next_hop4, 4);
        add_attr_value(hdr, value, 9);
    } else if (afi == IPV6_AFI) {
        printf("Adding for IPv6 AFI\n");
        value[3] = 16;
        memcpy(&value[4], next_hop6, 16);
        add_attr_value(hdr, value, 21);
    }
    return 0;
}


int sr_policy_set_binding(struct tunnel_encap_sr_policy *srp, __u32 binding_sid) {
    if (!srp)
        return -1;
    srp->binding.type = 13;
    srp->binding.length = 6;
    srp->binding.flags = 0;
    __u8 *sid = (__u8*)&binding_sid;
    srp->binding.sid = (__u32)(sid[0]) << 16 | (__u32)(sid[1]) << 8 | (__u32)(sid[2]);
    return 0;
}

void add_tunnel_encap_attribute(struct bgp_header *hdr) {
    add_attrib_hdr(hdr, FLAG_OPTIONAL|FLAG_TRANSITIVE, TUNNEL_ENCAP_ATTRIBUTE);
    increment_lengths(hdr, 2);
}

int append_sr_tunnel_tlv(struct bgp_header *hdr) {
    char *attr = bgp_find_attribute(hdr, TUNNEL_ENCAP_ATTRIBUTE);
    if (!attr)
        return -1;
    *(__u16*)&attr[3] = htons(15);
    *(__u16*)&attr[5] = 0;
    attr[2] += 4;
    increment_lengths(hdr, 4);
    return 0;
}

int append_tunnel_encap_preference_tlv(struct bgp_header *hdr, const __u32 preference) {
    char *attr = bgp_find_attribute(hdr, TUNNEL_ENCAP_ATTRIBUTE);
    if (!attr)
        return -1;
    char *attr_len_p = &attr[2];
    __u16 *tunnel_encap_len_p = (__u16*)&attr[5];
    char *data_ptr = attr+(*attr_len_p)+3;
    struct sr_preference_tlv srp = {0};
    srp.type = 12;
    srp.preference = htonl(preference);
    srp.length = 6;
    memcpy(data_ptr, &srp, sizeof(srp));
    *attr_len_p += 8;
    *tunnel_encap_len_p = htons(ntohs(*tunnel_encap_len_p)+8);
    increment_lengths(hdr, 7);
    return 0;
}

int append_tunnel_encap_priority_tlv(struct bgp_header *hdr, const __u8 priority) {
    char *attr = bgp_find_attribute(hdr, TUNNEL_ENCAP_ATTRIBUTE);
    if (!attr)
        return -1;
    char *attr_len_p = &attr[2];
    __u16 *tunnel_encap_len_p = (__u16*)&attr[5];
    char *data_ptr = attr+(*attr_len_p)+3;
    struct sr_priority_tlv srp = {0};
    srp.type = 15;
    srp.length = 2;
    srp.priority = priority;
    memcpy(data_ptr, &srp, sizeof(srp));
    *tunnel_encap_len_p = htons(ntohs(*tunnel_encap_len_p)+4);
    *attr_len_p += 4;
    increment_lengths(hdr, 4);
    return 0;
}

int append_tunnel_encap_binding4_tlv(struct bgp_header *hdr, const __u32 binding_sid) {
    char *attr = bgp_find_attribute(hdr, TUNNEL_ENCAP_ATTRIBUTE);
    if (!attr)
        return -1;
    char *attr_len_p = &attr[2];
    __u16 *tunnel_encap_len_p = (__u16*)&attr[5];
    char *data_ptr = attr+(*attr_len_p)+3;
    struct sr_binding_tlv srb = {0};
    srb.type = 13;
    srb.length = 6;
    srb.flags = 0;
    __u8 *sid = (__u8*)&binding_sid;
    srb.sid = (__u32)(sid[0]) << 16 | (__u32)(sid[1]) << 8 | (__u32)(sid[2]);
    memcpy(data_ptr, &srb, sizeof(srb));
    *attr_len_p += 8;
    *tunnel_encap_len_p = htons(ntohs(*tunnel_encap_len_p)+8);
    increment_lengths(hdr, 8);
    return 0;
}

int append_segment_list_tlv(struct bgp_header *hdr, const int n_sids, const __u32 *sid_list,
    const bool add_weight, const __u32 weight) {
    char *attr = bgp_find_attribute(hdr, TUNNEL_ENCAP_ATTRIBUTE);
    if (!attr)
        return -1;
    int increment_len = 4; // Minimum size
    char *attr_len_p = &attr[2];
    __u16 *tunnel_encap_len_p = (__u16*)&attr[5];
    char *data_ptr = attr+(*attr_len_p)+3;
    struct sr_segment_list srl = {0};
    srl.type = 128;
    memcpy(data_ptr, &srl, sizeof(srl));
    __u16 *sr_list_len_p = (__u16*)&data_ptr[1];
    char *srp = &data_ptr[4];
    if (add_weight) {
        struct sr_weight_tlv srw = {0};
        srw.type = 9;
        srw.length = 6;
        srw.weight = htonl(weight);
        memcpy(srp, &srw, 8);
        srp+=8;
        *sr_list_len_p = htons(ntohs(*sr_list_len_p)+8);
        increment_len+=8;
    }
    if (n_sids > 0 && sid_list) {
        for (int i = 0; i < n_sids; i++) {
            struct sr_sid_type_a srs = {0};
            srs.type = 1;
            srs.length = 6;
            srs.flags = 0;
            const __u8 *sid =  (__u8*)&sid_list[i];
            srs.label = (__u32)(sid[0]) << 16 | (__u32)(sid[1]) << 8 | (__u32)(sid[2]);
            srs.label = srs.label >> 8;
            memcpy(srp, &srs, 8);
            srp+=8;
            *sr_list_len_p = htons(ntohs(*sr_list_len_p)+8);
            increment_len+=8;
        }
    }
    *attr_len_p += increment_len;
    *tunnel_encap_len_p = htons(ntohs(*tunnel_encap_len_p)+increment_len);
    increment_lengths(hdr, increment_len);
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
    add_mp_bgp(hdr,IPV4_AFI, SR_POLICY_SAFI, "10.10.10.10");
    add_sr_policy_nlri(hdr, IPV4_AFI, 10, 10, "10.10.10.10");
    add_route_target4(hdr, "10.20.30.1", 0);
    add_asn(hdr, 65001);
    add_asn(hdr, 65002);
    add_tunnel_encap_attribute(hdr);
    append_sr_tunnel_tlv(hdr);
    append_tunnel_encap_preference_tlv(hdr, 100);
    append_tunnel_encap_priority_tlv(hdr, 10);
    append_tunnel_encap_binding4_tlv(hdr, 1000000);
    __u32 sid_list[3] = { 16002, 16003, 16033 };
    append_segment_list_tlv(hdr, 3, (__u32*)sid_list, true, 20);
    dump_buffer(hdr, ntohs(hdr->length));
}
