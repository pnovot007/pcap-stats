CC=gcc
CFLAGS= -std=c99 -pedantic -Wall -Wextra -g
#CFLAGS += -DDEBUG

pcap_stat: pcap_stat.o stat_list.o
	$(CC) $(CFLAGS) pcap_stat.o stat_list.o -o pcap_stat.exe

pcap_stat.o: pcap_stat.c pcap_stat.h stat_list.h
	$(CC) $(CFLAGS) -c pcap_stat.c -o pcap_stat.o

stat_list.o: stat_list.c stat_list.h
	$(CC) $(CFLAGS) -c stat_list.c -o stat_list.o

clean:
	rm -f pcap_stat.exe *.o

