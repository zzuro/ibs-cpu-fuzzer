#pragma once

#include "ktypes.h"

typedef struct io_driver_config {
    void (*_init_driver)(void);
    void (*_putchar)(u8 chr);
} io_driver_config_t;

void io__set_driver(io_driver_config_t new_driver);
void io__init_driver(void);
void io__putchar(int c);
void io__puts(const char* s);

void io__driver_putchar(io_driver_config_t* driver, int c);
void io__driver_puts(io_driver_config_t* driver, const char* s);

void putchar(int c);
void puts(const char* s);