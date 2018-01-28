sniff: sniff.c sniffcli.c sniff.h
	gcc -o sniff sniff.c isrunning.c -lpcap
	gcc -o sniffcli sniffcli.c isrunning.c -lpcap