#include "serial.h"
#include "ktypes.h"
#include "io.h"
#include "ports.h"

static const u16 serial_port = 0x3F8;

void serial_init(void){

   outb(serial_port + 1, 0x00);    // Disable all interrupts
   outb(serial_port + 3, 0x80);    // Enable DLAB (set baud rate divisor)
   outb(serial_port + 0, 0x03);    // Set divisor to 3 (lo byte) 38400 baud
   outb(serial_port + 1, 0x00);    //                  (hi byte)
   outb(serial_port + 3, 0x03);    // 8 bits, no parity, one stop bit
   outb(serial_port + 2, 0xC7);    // Enable FIFO, clear them, with 14-byte threshold
   outb(serial_port + 4, 0x0B);    // IRQs enabled, RTS/DSR set
   outb(serial_port + 4, 0x1E);    // Set in loopback mode, test the serial chip
   //outb(serial_port + 0, 0xAE);    // Test serial chip (send byte 0xAE and check if serial returns same byte)
   outb(serial_port + 4, 0x0F);
}

static bool is_transmit_empty(void) {
   return inb(serial_port + 5) & 0x20;
}
 
void serial_putchar(u8 a) {
   while(!is_transmit_empty());
   outb(serial_port,a);
}

void serial_puts(const char* str){
   while(*str != '\0'){
      serial_putchar(*str);
      str++;
   }
}

void serial_print_addr(void* ptr){
    u64 addr = (u64)ptr;
    serial_putchar('0');
    serial_putchar('x');
    for(i8 shift = 64-4; shift >= 0; shift -= 4){
        u8 nibble = (u8)(addr>>shift)&0xf;
        serial_putchar(nibble >= 10 ? nibble-10+'a' : nibble+'0');
    }
}

void serial_print_hex64(u64 val){
    u64 addr = val;
    serial_putchar('0');
    serial_putchar('x');
    for(i8 shift = 64-4; shift >= 0; shift -= 4){
        u8 nibble = (u8)(addr>>shift)&0xf;
        serial_putchar(nibble >= 10 ? nibble-10+'a' : nibble+'0');
    }
}

void serial_print_hex32(u32 val){
    u32 addr = val;
    serial_putchar('0');
    serial_putchar('x');
    for(i8 shift = 32-4; shift >= 0; shift -= 4){
        u8 nibble = (u8)(addr>>shift)&0xf;
        serial_putchar(nibble >= 10 ? nibble-10+'a' : nibble+'0');
    }
}
void serial_print_hex16(u16 val){
    u16 addr = val;
    serial_putchar('0');
    serial_putchar('x');
    for(i8 shift = 16-4; shift >= 0; shift -= 4){
        u8 nibble = (u8)(addr>>shift)&0xf;
        serial_putchar(nibble >= 10 ? nibble-10+'a' : nibble+'0');
    }
}

void serial_print_hex8(u8 val){
    u8 addr = val;
    serial_putchar('0');
    serial_putchar('x');
    for(i8 shift = 8-4; shift >= 0; shift -= 4){
        u8 nibble = (u8)(addr>>shift)&0xf;
        serial_putchar(nibble >= 10 ? nibble-10+'a' : nibble+'0');
    }
}

io_driver_config_t serial__get_serial_driver(void){

   io_driver_config_t drv = {
        ._init_driver = serial_init,
        ._putchar = serial_putchar
    };
    
    return drv;
}

void serial_print_bytestring(const char* name, const u8* content, size_t len) {
    serial_puts(name);
    serial_puts("='");
    for(size_t i = 0; i < len; i++){
        if(i > 0) {
            serial_putchar(' ');
        }
        serial_print_hex8(content[i]);
    }
    serial_puts("'\n");
}
