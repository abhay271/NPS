CC = gcc
CFLAGS = -Wall -O2

ifeq ($(OS),Windows_NT)
LDFLAGS = -lws2_32
else
LDFLAGS =
endif

all: sender receiver

sender: sender.c
	$(CC) $(CFLAGS) -o sender sender.c $(LDFLAGS)

receiver: receiver.c
	$(CC) $(CFLAGS) -o receiver receiver.c $(LDFLAGS)

ifeq ($(OS),Windows_NT)
clean:
	-del /Q sender.exe receiver.exe sender receiver 2>NUL
else
clean:
	rm -f sender receiver sender.exe receiver.exe
endif
