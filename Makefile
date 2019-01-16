CC = gcc
CFLAGS = -Wall -Wextra -Wconversion -pedantic  #The new Wconversion option warns for any IMPLICIT conversion that MAY change a value#
#DEPS = sniffer.h# #$(DEPS)#
LIBS = -lpcap
OBJ = sniffer-0.75.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
	
sniffer: $(OBJ)
	$(CC) -o $@ $^ $(LIBS)
	$(MAKE) clean
	
clean:
	rm -f *.o
