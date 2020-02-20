#include <stdio.h>
#include <string.h>

#include "pcap_stat.h"
#include "stat_list.h"

int main ()
{

    char * pcapfile = "input.pcap"; 
    FILE * fptr;
    char frame_buff[64*1024];
    
    pcap_hdr_t pcap_hdr;
    memset(&pcap_hdr, 0, sizeof(pcap_hdr_t));
    
    pcaprec_hdr_t pcaprec_hdr;
    memset(&pcaprec_hdr, 0, sizeof(pcaprec_hdr_t));
    
    uint32_t pckt_cnt=0;

    uint32_t src_ip=0;

    uint32_t timestamp=0;
    uint32_t obs_time=10;
    

    stat_list_s * stat_list = stat_list_create();


    printf("Opening file...\n");
    fptr = fopen(pcapfile,"rb");
 
 
    printf("Reading header...\n");
 
    fread(&pcap_hdr, sizeof(pcap_hdr_t), 1, fptr);

    printf("magic_number: %lu\n", pcap_hdr.magic_number);
    printf("version_major: %lu\n", pcap_hdr.version_major);
    printf("version_minor: %hu\n", pcap_hdr.version_minor);
    printf("thiszone: %ld\n", pcap_hdr.thiszone);
    printf("sigfigs: %lu\n", pcap_hdr.sigfigs);
    printf("snaplen: %lu\n", pcap_hdr.snaplen);
    printf("network: %lu\n", pcap_hdr.network);
    printf("=============================\n");

    printf("Reading network frames...\n");
 
    while (1) 
    {
        pckt_cnt++;


        if (fread(&pcaprec_hdr, sizeof(pcaprec_hdr_t), 1, fptr) == 0) break;

#if defined DEBUG
        printf("Packet number: %lu\n", pckt_cnt);
        printf("ts_sec: %lu\n", pcaprec_hdr.ts_sec);
        printf("ts_usec: %lu\n", pcaprec_hdr.ts_usec);
        printf("incl_len: %lu\n", pcaprec_hdr.incl_len);
        printf("orig_len: %lu\n", pcaprec_hdr.orig_len);
#endif

        /* Init timestamp */
        if (timestamp == 0) timestamp = pcaprec_hdr.ts_sec;

        /* Flush statistics*/
        if (pcaprec_hdr.ts_sec >= timestamp + obs_time){
            printf("\n%lu\n------------------------\n", timestamp);
            stat_list_print(stat_list);
            stat_list_destroy(stat_list);
            stat_list = stat_list_create();
            timestamp = pcaprec_hdr.ts_sec;
        }

        fread(frame_buff, pcaprec_hdr.incl_len, 1, fptr);
        ((char *)&src_ip)[3]=frame_buff[26];
        ((char *)&src_ip)[2]=frame_buff[27];
        ((char *)&src_ip)[1]=frame_buff[28];
        ((char *)&src_ip)[0]=frame_buff[29];
        
#if defined DEBUG
        printf("............................\n");       
        printf("ts_sec: %lu\n", pcaprec_hdr.ts_sec);
        printf("src_ip: %x\n", src_ip);
        printf("----------------------------\n\n\n");       
#endif

        stat_list_add_entry(stat_list, src_ip);
 
#if defined DEBUG       
        stat_list_print(stat_list);
#endif

    }


        printf("\n%lu\n------------------------\n", timestamp);
        stat_list_print(stat_list);
        stat_list_destroy(stat_list);



    printf("Closing file...\n");
 
    fclose(fptr);

    return 0;
}
