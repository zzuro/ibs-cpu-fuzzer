CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11
LDFLAGS := 

# Targets
SAMPLER := sampling
WORKLOADS := ibs_workload_cache ibs_workload_store

# Sources
SAMPLER_SRC := sampling.c
WORKLOAD_CACHE_SRC := ibs_workload_cache.c
WORKLOAD_STORE_SRC := ibs_workload_store.c

.PHONY: all clean debug

# Build everything
all: $(SAMPLER) $(WORKLOADS)

# Sampler
$(SAMPLER): $(SAMPLER_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Cache workload
ibs_workload_cache: $(WORKLOAD_CACHE_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Store workload
ibs_workload_store: $(WORKLOAD_STORE_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Debug build (rebuild everything with -O0 -g)
debug: CFLAGS := -O0 -g -Wall -Wextra -std=c11
debug: clean all

clean:
	rm -f $(SAMPLER) $(WORKLOADS)
