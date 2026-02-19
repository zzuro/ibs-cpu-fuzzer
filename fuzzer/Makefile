# Compiler
CC := gcc

# Output binaries
TARGET := injector
GUEST  := guest

# Source files
SRCS := injector.c
GUEST_SRCS := guest.c

OBJS := $(SRCS:.c=.o)
GUEST_OBJS := $(GUEST_SRCS:.c=.o)

# Compiler flags
CFLAGS := -Wall -Wextra -Wpedantic -O2 -g -std=gnu11

# Linker flags
LDFLAGS := -pthread

# Default target
all: $(TARGET) $(GUEST)

# Link injector
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Link guest test
$(GUEST): $(GUEST_OBJS)
	$(CC) $(GUEST_OBJS) -o $(GUEST)
	scp -P 2222 $(GUEST) ubuntu@localhost:/home/ubuntu/

# Compile rule
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -f $(OBJS) $(GUEST_OBJS) $(TARGET) $(GUEST)

# Rebuild
re: clean all

.PHONY: all clean re
