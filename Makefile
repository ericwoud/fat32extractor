
CC = gcc
CFLAGS = -Wall -I.
LDFLAGS =
OBJFILES = lib/fat32.o fat32extractor.o
TARGET = fat32extractor

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET) *~

