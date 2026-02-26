#include "io.h"
#include "ktypes.h"

static io_driver_config_t current_io_driver = {
    ._init_driver = 0,
    ._putchar = 0
};


void io__set_driver(io_driver_config_t new_driver){
    current_io_driver = new_driver;
}

void io__init_driver(void){
    current_io_driver._init_driver();
}

void io__putchar(int c){
    current_io_driver._putchar((u8)c);
}


void io__puts(const char* s){
    while(*s != '\0'){
        io__putchar(*(s++));
    }
}

void putchar(int c){
    io__putchar(c);
}

void puts(const char* s){
    io__puts(s);    
}

void io__driver_putchar(io_driver_config_t* driver, int c){
    driver->_putchar(c);
}

void io__driver_puts(io_driver_config_t* driver, const char* s){
    while(*s != '\0'){
        io__driver_putchar(driver, *(s++));
    }
}
