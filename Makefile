CC=gcc
CFLAGS= -std=c99 -pedantic -Wall -Wextra -g


pcap_stat: pcap_stat.c pcap_stat.h
	$(CC) $(CFLAGS) pcap_stat.c -o pcap_stat.exe

clean:
	rm -f $(NAME).exe   # smaže binární soubor

