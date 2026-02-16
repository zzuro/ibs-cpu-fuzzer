CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11
LDFLAGS := 
TARGET  := sampling
SRC     := sampling.c

.PHONY: all clean debug

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

debug: CFLAGS := -O0 -g -Wall -Wextra -std=c11
debug: clean $(TARGET)

clean:
	rm -f $(TARGET)