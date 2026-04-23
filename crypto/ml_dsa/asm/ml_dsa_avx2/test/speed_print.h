#ifndef PRINT_SPEED_H
#define PRINT_SPEED_H

#include <stddef.h>
#include <stdint.h>

/* Activate when interested in CSV results
#define CSV_PRINT
*/


void print_results(const char *s, uint64_t *t, size_t tlen);

#endif
