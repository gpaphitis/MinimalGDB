CC = gcc
CFLAGS = -Wall -Werror -g
LDFLAGS = -lelf -lcapstone
SRC = mdb.c breakpoints.c elfloader.c disassembler.c inputparser.c
OBJ = $(SRC:.c=.o)
TARGET = mdb

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
