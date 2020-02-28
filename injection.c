// jprx procinject
// LD_PRELOAD code injection & hooking library
// Uses libfunchook for function hooking (https://github.com/kubo/funchook)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uintptr_t
#include <funchook.h>

#include "injection.h"
#include "userpref.h"

// Permission vector
#define PERM_R (1 << 0)
#define PERM_W (1 << 1)
#define PERM_X (1 << 2)
#define PERM_P (1 << 3)

// Linked list of known page entries
static page_entry *found_pages = NULL;

// Strip path down to last substring after & including final '/'
// Returns pointer to original string if no '/' found
const char* get_filename_from_path(const char* path) {
	const char* cursor = path;
	while (cursor && *(path+1) && (cursor = strchr(path+1,(int)'/'))) {
		if (cursor) path = cursor;
	}
	return path;
}

// Strip trailing newline character in string
char* strip_trailing_newline(char* str) {
	if (!str || 1 >= strlen(str)) return str;
	char* cursor = (char*)(str + strlen(str) - 1);
	if (cursor[0] == '\n') cursor[0] = '\0';
	return str;
}

// Dan Bernstein's djb2 hash algorithm
unsigned long djb2_hash (const char* s) {
	unsigned long hash = 5381;
	int c;
	while (s && (c = *s++)) { hash = ((hash << 5) + hash) + c; }
	return hash;
}

// Construct a page_entry
page_entry *create_page_entry(char *s, char *e, unsigned long h) {
	page_entry *p = (page_entry*)malloc(sizeof(*p));
	if (p) {
		p->start = s;
		p->end = e;
		p->name_hash = h;
		p->next = NULL;
		p->perm_vector = 0;
		p->is_exec = 0;

		// Insert into list:
		p->next = found_pages;
		found_pages = p;
	}
	return p;
}

// Destroy a page_entry
void destroy_page_entry (page_entry *p) {
	free(p);
}

// Set permission bits of a page table entry
void save_page_perms (page_entry *pe, uint8_t r, uint8_t w, uint8_t x, uint8_t p) {
	if (!pe) return;
	pe->perm_vector |= (r == 'r') ? PERM_R : 0;
	pe->perm_vector |= (w == 'w') ? PERM_W : 0;
	pe->perm_vector |= (x == 'x') ? PERM_X : 0;
	pe->perm_vector |= (p == 'p') ? PERM_P : 0;
	pe->is_exec = (pe->perm_vector & PERM_X) != 0;
}

// Pretty-print all pages we found from last scan
void print_pages(void) {
	page_entry *cur_page = found_pages;
	while (cur_page) {
		fprintf(stdout, "%p\t\t%p\t\t%lu\n", cur_page->start, cur_page->end, cur_page->name_hash);
		cur_page = cur_page->next;
	}
}

// Scan pages & create list of definitions
int scan_pages(void) {
	FILE *fd;
	// Hopefully /proc/self/maps doesn't give more than 2048 bytes/line
	char buf[2048];
	char *start_addr, *fin_addr;
	int count = 0;
	char perm_w, perm_r, perm_x, perm_p;

	fd = fopen("/proc/self/maps", "r");
	if (!fd) {return -1;}
	
	// Scan allocated pages & store in list
	while (fscanf(fd, "%p-%p %c%c%c%c", &start_addr, &fin_addr, &perm_r, &perm_w, &perm_x, &perm_p)) {
		// Scan to end of line:
		if (!fgets(buf,sizeof(buf),fd)) {break;}

		// Get name of the binary that this proc is for:
		const char* name = strchr(buf,(int)'/');
		name = get_filename_from_path(name);	
		name = (const char*)strip_trailing_newline((char*)name); // name is const... but not here tho

		//fprintf(stdout, "Found %s (%lu)\n", name, djb2_hash(name));

		// Hash binary name
		unsigned long name_hash = djb2_hash(name);

		// Store pages into database:
		page_entry *new_page = create_page_entry(start_addr, fin_addr, name_hash);
		save_page_perms(new_page, perm_r, perm_w, perm_x, perm_p);
		count++;
	}
	return count;
}

// library_hash: djb2 hash of the name of the library to scan for
// page_offset: offset of the method within the page (4 kB pages) to find
void* scan_for_signature (unsigned long library_hash, u_int32_t page_offset) {
	// Scan for pattern in all pages mapping to desired process binary name hash
	page_entry *cur_page = found_pages;
	unsigned long target_hash = library_hash;
	page_offset &= 0x0FFF; // Lowest 12 bits of general offset = offset into whatever page the sequence was loaded into
	while (cur_page) {
		if (cur_page->name_hash == target_hash) {
			// Only scan each page at the known offset:
			char* addr = cur_page->start + page_offset;
			char *addr_tmp = addr;
			int i = 0;
			int found = 1;
			if (addr && *addr == sequence_to_detect[0]) {
				for (i = 0; i < strlen(sequence_to_detect); i++) {
					//if (addr_tmp > cur_page->end) { fprintf(stdout, "[ERROR] Sequence lies at page boundary?\n"); exit (-1); }
					if (addr_tmp && *addr_tmp != sequence_to_detect[i]) { found = 0; break; }
					addr_tmp++;
				}
				if (found) {
					// Ensure this is the exact match by checking the static bits of virtual address
					// This is because there may be false positives that have similar signatures
					if (!(((uintptr_t)addr & 0x0FFF) ^ page_offset)) {
						void *fp = (void*)addr;

						// Only return pointer if the page is executable
						// Copies of binary will contain the same signature in non-exec memory
						// We don't care about those though
						if (cur_page->is_exec) return (void*)fp;
					}
				}
			}
		}
		cur_page = cur_page->next;
	}
}

// Hook pointer (used for trampoline, will point to original def)
static hook_fn_ptr_t hook_ptr;

// Hook a target function using libfunchook
int hook_fn(void *func_to_hook, void* hook_handler) {
	funchook_t *f = funchook_create();
	hook_ptr = (hook_fn_ptr_t)func_to_hook;
	if (0 != funchook_prepare(f, (void**)&(hook_ptr), (hook_fn_ptr_t)hook_handler)) {
		fprintf(stdout, "[injector.so] Error hooking function\n");
		return 0;
	}
	funchook_install(f,0);
	fprintf(stdout, "Hahaha I hijacked your 'findme' function\n");
}

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
void inject (unsigned long binary_name_hash, const char* sequence, uint32_t page_offset, void *hook_handler) {
	void* found_fn = NULL;
	page_offset &= 0x0FFF;	// Mask out all but lower 12 bits for 4kb page
	scan_pages();
	found_fn = scan_for_signature(binary_name_hash, page_offset);
	if (found_fn) hook_fn(found_fn, hook_handler);
}
