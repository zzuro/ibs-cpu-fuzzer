CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11
LDFLAGS := 

# Targets
FUZZER_STATE := fuzzer-state

# Sources
FUZZER_STATE_SRC := fuzzer-state.c

.PHONY: all clean debug

# Build everything
all: $(FUZZER_STATE)

# FUZZER_STATE
$(FUZZER_STATE): $(FUZZER_STATE_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)


# Debug build (rebuild everything with -O0 -g)
debug: CFLAGS := -O0 -g -Wall -Wextra -std=c11
debug: clean all

clean:
	rm -f $(FUZZER_STATE)
