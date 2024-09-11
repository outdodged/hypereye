#include <utils.h>

uint16_t get_ldt_selector(void) {
	uint16_t ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}