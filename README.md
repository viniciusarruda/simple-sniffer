# A simple sniffer written in C

To compile: run `make`

To run: `sudo ./sniffer wlan0`

The `sudo` is necessary to use the network card in promiscuous mode. The first parameter is the active network interfaces to be listened (e.g., eth0, lo, wlan0).

The program prints the captured packets on screen and produces three files:

* `pcapfile.pcap`: A file in the pcap format, ready to be used with Wireshark or other similar softwares.
* `raw_logfile.txt`: A file with the raw output of the captured packets, containing the content in hexadecimal and in string format.
* `logfile.txt`: A file with the log of the captured packets showing some content inside it, for example, MAC destination and source addresses.
