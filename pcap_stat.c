#include <stdio.h>
#include <string.h>

#include "pcap_stat.h"

int main ()
{

    char * pcapfile = "input.pcap"; 
    FILE * fptr;
    char buffer[64*1024];
    
    pcap_hdr_t pcap_hdr;
    memset(&pcap_hdr, 0, sizeof(pcap_hdr_t));
    
    pcaprec_hdr_t pcaprec_hdr;
    memset(&pcaprec_hdr, 0, sizeof(pcaprec_hdr_t));
    
    uint32_t pckt_cnt=0;

    uint32_t src_ip=0;


    printf("Opening file...");

    fptr = fopen(pcapfile,"rb");
    fread(&pcap_hdr, sizeof(pcap_hdr_t), 1, fptr);

    printf("magic_number: %lu\n", pcap_hdr.magic_number);
    printf("version_major: %lu\n", pcap_hdr.version_major);
    printf("version_minor: %hu\n", pcap_hdr.version_minor);
    printf("thiszone: %ld\n", pcap_hdr.thiszone);
    printf("sigfigs: %lu\n", pcap_hdr.sigfigs);
    printf("snaplen: %lu\n", pcap_hdr.snaplen);
    printf("network: %lu\n", pcap_hdr.network);
    printf("=============================\n");

    while (1) 
    {
        pckt_cnt++;


        if (fread(&pcaprec_hdr, sizeof(pcaprec_hdr_t), 1, fptr) == 0) break;

        printf("Packet number: %lu\n", pckt_cnt);
        printf("ts_sec: %lu\n", pcaprec_hdr.ts_sec);
        printf("ts_usec: %lu\n", pcaprec_hdr.ts_usec);
        printf("incl_len: %lu\n", pcaprec_hdr.incl_len);
        printf("orig_len: %lu\n", pcaprec_hdr.orig_len);
        
        
        fread(buffer, pcaprec_hdr.incl_len, 1, fptr);
        ((char *)&src_ip)[3]=buffer[26];
        ((char *)&src_ip)[2]=buffer[27];
        ((char *)&src_ip)[1]=buffer[28];
        ((char *)&src_ip)[0]=buffer[29];
        
        //memcpy(&src_ip, &buffer[26], 4);
        /*src_ip = ((* ip_addr_mask_t) buffer)->src_ip;
        */
        printf("............................\n");       

        printf("ts_sec: %lu\n", pcaprec_hdr.ts_sec);
        printf("src_ip: %x\n", src_ip);

        printf("----------------------------\n");       

    }



    fclose(fptr);

    return 0;
}
