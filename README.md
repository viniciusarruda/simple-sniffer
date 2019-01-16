# A simple sniffer written in C

To compile: run `make`

To run: `sudo ./sniffer`

The `sudo` is necessary to use the network card in promiscuous mode, otherwise, only networks without need to run in promiscuous mode will be shown (e.g., bluetooth).

To stop the capture: `ctrl + z`.

The program prints the captured packets on screen and produces three files (its name must be entered by the program):

* `pcapfile.pcap`: A file in the pcap format, ready to be used with Wireshark or other similar softwares.
* `raw_logfile.txt`: A file with the raw output of the captured packets, containing the content in hexadecimal and in string format.
* `logfile.txt`: A file with the log of the captured packets showing some content inside it.

At the end of the program, the user will be asked if wants to merge the files `raw_logfile.txt` and `logfile.txt`.

