#include <stdint.h>
#include <stddef.h>


typedef struct stat_list_entry_s stat_list_entry_s;

struct stat_list_entry_s{
        uint32_t ip_addr;
        uint32_t cnt;
        stat_list_entry_s * prev;
        stat_list_entry_s * next;
};

typedef struct stat_list_s {
        stat_list_entry_s * first;
        stat_list_entry_s * last;        
} stat_list_s;

stat_list_s * stat_list_create ();

void stat_list_destroy (stat_list_s * stat_list);

void stat_list_add_entry (stat_list_s * stat_list, uint32_t ip_addr);

void stat_list_sort_desc(stat_list_s * stat_list);

uint32_t stat_list_pop(stat_list_s * stat_list, uint32_t * ip_ptr);

uint32_t stat_list_length (stat_list_s * stat_list);

void stat_list_print (stat_list_s * stat_list);

