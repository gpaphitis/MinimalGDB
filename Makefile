CC = gcc
CFLAGS = -Wall -Werror -g
LDFLAGS = -lelf -lcapstone
SRC = mdb.c breakpoints.c elfloader.c disassembler.c
OBJ = $(SRC:.c=.o)
TARGET = mdb
TARBALL = mdb_UC1065009.tar.gz
FILES = mdb.c breakpoints.c disassembler.c elfloader.c Makefile

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

tarball:
	tar -cvzf $(TARBALL) $(FILES)

.PHONY: all clean tarball