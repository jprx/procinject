// jprx procinject
// LD_PRELOAD code injection & hooking library
// Uses libfunchook for function hooking (https://github.com/kubo/funchook)
#include "injection.h"

// First few bytes of a target structure:
const char sequence_to_detect[100] = "\x55\x48\x89\xe5\x89\x7d\xfc\x8b\x45\xfc\x5d";

// Offset of the sequence into the binary:
// (Only lower 12 bits are used in scanning assuming 4kb page sizes)
#define SEQUENCE_OFFSET 0x68a

// The name of the binary to which the pages to be search belongs
#define BINARY_NAME "/target"

// Define hook type here:
typedef int (*hook_fn_ptr_t)(int a);

// Hooked function goes here:
int hooked_findme2 (int a) {
	return 420;
}

// Define the overridden function here (must be exported symbol):
int puts (const char* c) {
	inject(djb2_hash(BINARY_NAME), sequence_to_detect, SEQUENCE_OFFSET, hooked_findme2);
}
