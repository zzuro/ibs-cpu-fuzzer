#pragma once

#include "io.h"

io_driver_config_t serial__get_serial_driver(void);
void serial_init(void);
void serial_putchar(u8 a);
void serial_puts(const char* str);
void serial_print_addr(void* ptr);

void serial_print_hex64(u64 val);
void serial_print_hex32(u32 val);
void serial_print_hex16(u16 val);
void serial_print_hex8(u8 val);

void serial_print_bytestring(const char* name, const u8* content, size_t len);