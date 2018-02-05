sniff: sniff.c sniffcli.c sniff.h
	gcc -pthread -o sniff sniff.c -lpcap
	gcc -o sniffcli sniffcli.c
