// jprx procinject
// LD_PRELOAD code injection & hooking library
#ifndef JPRX_INJECTION_H
#define JPRX_INJECTION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <funchook.h>

/*
 * inject
 * Locate a sequence in a given binary & override it with a given function
 *
 * Inputs:
 * binary_name_hash - djb2 hash of the shared object to find
 * sequence         - pointer to a buffer containing sequence to compare against
 * page_offset      - offset into a 4kb page that the sequence can be found at
 * hook_handler     - definition of new function to replace old one
 *
 * Returns:
 * None
 *
 * Side-effects:
 * Hooks the given function or prints error message
 */
void inject (unsigned long binary_name_hash, const char* sequence, uint32_t page_offset, void *hook_handler);

// Page table entry data structure- keep a list of these
typedef struct page_entry_t {
	char *start, *end;
	unsigned long name_hash;
	struct page_entry_t *next;
	uint8_t perm_vector;
	uint8_t is_exec;	// Is this PTE executable?
} page_entry;

// Strip path down to last substring after & including final '/'
// Returns pointer to original string if no '/' found
const char* get_filename_from_path(const char* path);

// Strip trailing newline character in string
char* strip_trailing_newline(char* str);

// Dan Bernstein's djb2 hash algorithm
unsigned long djb2_hash (const char* s);

// Construct a page_entry
page_entry *create_page_entry(char *s, char *e, unsigned long h);

// Destroy a page_entry
void destroy_page_entry (page_entry *p);

// Set permission bits of a page table entry
void save_page_perms (page_entry *pe, uint8_t r, uint8_t w, uint8_t x, uint8_t p);

// Pretty-print all pages we found from last scan
void print_pages(void);

// Hook a target function using libfunchook
int hook_fn(void *func_to_hook, void* hook_handler);

#endif

