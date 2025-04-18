#include <stdint.h>

// depends on the need of batch executions, may be reduced to char (e.g., for challenge submission)
typedef uint64_t WORD;

// if circuit requires more memory than 2^16 bits, need to change this
typedef uint16_t ADDR;

// unlikely that there are more opcodes (and serialization method relies on this structure...)
typedef uint8_t BYTE;

typedef struct {
    uint64_t input_size;
    uint64_t output_size;
    uint64_t num_opcodes;
    uint64_t opcodes_size;
    uint64_t memory;
} CircuitInfo;

typedef struct {
    CircuitInfo info;
    ADDR *input_addr;
    ADDR *output_addr;
    BYTE *opcodes;
    WORD *ram;
} Circuit;

enum OP {_, XOR, AND, OR, NOT, RANDOM};

void __attribute__ ((constructor)) set_seed_time();
void set_seed(uint64_t seed);
WORD randbit();

Circuit *load_circuit(char *fname);
void free_circuit(Circuit *C);
void circuit_compute(Circuit *C, uint8_t *inp, uint8_t *out, char *trace_filename, int batch);
