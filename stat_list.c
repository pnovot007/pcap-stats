#include <stdlib.h>
#include <stdio.h>
#include "stat_list.h"


stat_list_s * stat_list_create () {

    stat_list_s * stat_list = (stat_list_s *) malloc(sizeof(stat_list_s));
    stat_list->first=NULL;
    stat_list->last=NULL;

#if defined DEBUG
        printf(">>> stat_list_create () returns: 0x%x\n", stat_list);
#endif
    return stat_list;
}

void stat_list_destroy (stat_list_s * stat_list){

    stat_list_entry_s * stat_list_entry;
    while ((stat_list_entry = stat_list->first))
    {
        stat_list->first = stat_list_entry->next;
        free(stat_list_entry);
    }

    free (stat_list);
}


void stat_list_add_entry (stat_list_s * stat_list, uint32_t ip_addr) {

#if defined DEBUG
    printf(">>> stat_list_add_entry () entered, stat_list=0x%x, ip_addr=0x%x\n", stat_list, ip_addr);
#endif
    stat_list_entry_s * stat_list_entry = stat_list->first;
    int entry_found = 0;
    while (stat_list_entry != NULL)
    {
        if(stat_list_entry->ip_addr == ip_addr)
        {
            stat_list_entry->cnt++;
            entry_found = 1;
#if defined DEBUG
    printf(">>> stat_list_add_entry () entry found, incrementing counter, stat_list=0x%x, ip_addr=0x%x\n", stat_list, ip_addr);
#endif            
            break;
        }
        stat_list_entry = stat_list_entry->next;
    }

    /* Create a new enry and append it to the list */
    if (!entry_found)
    {
#if defined DEBUG
    printf(">>> stat_list_add_entry () entry not found, adding..., stat_list=0x%x, ip_addr=0x%x\n", stat_list, ip_addr);
#endif
        stat_list_entry = (stat_list_entry_s *) malloc(sizeof(stat_list_entry_s));
        stat_list_entry->next = NULL;
        stat_list_entry->prev = stat_list->last;
        stat_list_entry->ip_addr = ip_addr;
        stat_list_entry->cnt = 1;
        if (stat_list->last) stat_list->last->next = stat_list_entry;
        if (!stat_list->first) stat_list->first = stat_list_entry;
        stat_list->last = stat_list_entry;
    }

}

void stat_list_sort_desc(stat_list_s * stat_list) {

#if defined DEBUG
    printf(">>> sstat_list_sort_desc () entered, stat_list=0x%x\n", stat_list);
#endif
    uint32_t length = stat_list_length(stat_list);
    uint32_t tmp_ip;
    uint32_t tmp_cnt;
    
    /* Bubble sort */
    for (uint32_t i=1; i<length; i++)
    {
        stat_list_entry_s * stat_list_entry = stat_list->first;
        for(uint32_t j=1; j<length-i; j++)
        {
            if (stat_list_entry->cnt < stat_list_entry->next->cnt){
                /* Switch data, do not modify the list */
                tmp_ip = stat_list_entry->ip_addr;
                tmp_cnt = stat_list_entry->cnt;
                stat_list_entry->ip_addr = stat_list_entry->next->ip_addr;
                stat_list_entry->cnt = stat_list_entry->next->cnt;
                stat_list_entry->next->ip_addr = tmp_ip;
                stat_list_entry->next->cnt = tmp_cnt;

            }
            stat_list_entry = stat_list_entry->next;
        }

    }

    return;
}

uint32_t stat_list_pop(stat_list_s * stat_list, uint32_t * ip_ptr){
/* Get the most frequent IP address and remove the record from the list */

#if defined DEBUG
    printf(">>> stat_list_pop () entered, stat_list=0x%x, ip_ptr=0x%x\n", stat_list, ip_ptr);
#endif

    stat_list_entry_s * stat_list_entry = stat_list->first;
    uint32_t cnt = stat_list_entry->cnt;
    * ip_ptr = stat_list_entry->ip_addr;

    stat_list->first = stat_list->first->next;
    if (stat_list->first != NULL) stat_list->first->next = NULL;
    free(stat_list_entry);

    return cnt;
}




uint32_t stat_list_length (stat_list_s * stat_list) {
/* Get the number of list elements */

    uint32_t length = 0;
    
    stat_list_entry_s * stat_list_entry = stat_list->first;

    while (stat_list_entry != NULL)
    {

        stat_list_entry = stat_list_entry->next;
        length++;
    }    

    return length;   
}

void stat_list_print (stat_list_s * stat_list){

#if defined DEBUG
    printf(">>> stat_list_print () entered, stat_list=0x%x\n", stat_list);
#endif
    
    
    stat_list_sort_desc(stat_list);
    
    stat_list_entry_s * stat_list_entry = stat_list->first;
    while (stat_list_entry != NULL)
    {
        /*printf("%lu\t%lu\n", stat_list_entry->cnt, stat_list_entry->ip_addr);*/
        printf("%lu\t%lu.%lu.%lu.%lu\n", stat_list_entry->cnt,
        stat_list_entry->ip_addr>>24, 
        stat_list_entry->ip_addr<<8>>24,
        stat_list_entry->ip_addr<<16>>24, 
        stat_list_entry->ip_addr<<24>>24);

        stat_list_entry = stat_list_entry->next;

    }

    return;
}