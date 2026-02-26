#pragma once

#include "ktypes.h"

struct memory_map_entry {
    u64 start; // start physical address
    u64 len;
};
typedef struct memory_map_entry memory_map_entry_t;
