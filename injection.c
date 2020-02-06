// Read proc self maps
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char sequence_to_detect[100] = "\x55\x48\x89\xe5\x48\x83\xec\x10\xc7\x45\xfc";

typedef struct page_entry_t {
	char *start, *end;
	unsigned long name_hash;
	struct page_entry_t *next;
} page_entry;

// Linked list of known page entries
page_entry *found_pages = NULL;

// Strip path down to last substring after & including final '/'
// Returns pointer to original string if no '/' found
const char* get_filename_from_path(const char* path) {
	const char* cursor = path;
	while (cursor && *(path+1) && (cursor = strchr(path+1,(int)'/'))) {
		if (cursor) path = cursor;
	}
	return path;
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

// Method to find in code segment
typedef int (*find_this_func)(void);
int find_me_you_wont (void) {
	int i = 0;
	for (i = 0; i < 5; i++) {
		printf("You found me!%d\n", i%2);
	}
}

void print_pages(void) {
	// Display all pages found:
	page_entry *cur_page = found_pages;
	while (cur_page) {
		fprintf(stdout, "%p\t\t%p\t\t%lu\n", cur_page->start, cur_page->end, cur_page->name_hash);
		cur_page = cur_page->next;
	}
}

char bigbuf[5000];

int scan_pages(void) {
	FILE *fd;
	// Hopefully /proc/self/maps doesn't give more than 2048 bytes/line
	char buf[2048];
	char *start_addr, *fin_addr;
	int count = 0;

	fd = fopen("/proc/self/maps", "r");
	if (!fd) {return -1;}
	
	// Scan allocated pages & store in list
	while (fscanf(fd, "%p-%p", &start_addr, &fin_addr)) {
		// Scan to end of line:
		if (!fgets(buf,sizeof(buf),fd)) {break;}

		// Get name of the binary that this proc is for:
		const char* name = strchr(buf,(int)'/');
		name = get_filename_from_path(name);	

		//fprintf(stdout, "Found %s (%lu)\n", name, djb2_hash(name));

		// Hash binary name
		unsigned long name_hash = djb2_hash(name);

		// Store pages into database:
		page_entry *new_page = create_page_entry(start_addr, fin_addr, name_hash);
		count++;
	}
	return count;
}

// library_hash: djb2 hash of the name of the library to scan for
// page_offset: offset of the method within the page (4 kB pages) to find
void* scan_for_signature (unsigned long library_hash, u_int32_t page_offset) {
	static int found_it_yet = 0;
	// Scan for pattern in all pages mapping to desired process binary name hash
	page_entry *cur_page = found_pages;
	unsigned long target_hash = library_hash;
	while (cur_page) {
		//fprintf(stdout, "\nSCANNING %p %lu", cur_page->start, cur_page->name_hash);
		if (cur_page->name_hash == target_hash) {
			for (char* addr = cur_page->start; addr < cur_page->end; addr++) {
				// Naive search algorithm for the moment, will replace with better method
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
						if (!(((int)addr & 0x0FFF) ^ page_offset)) {
							fprintf(stdout, "[injector.so] Found sequence at %p in page %p\n", addr, cur_page->start);
							find_this_func fp = (find_this_func)addr;
							if (found_it_yet) {
								fprintf(stdout, "[injector.so] Jumping to found sequence\n");
								fp();
							}

							found_it_yet = 1;
							//return (void*)fp;
						}
					}
				}
			}
		}
		cur_page = cur_page->next;
	}
}

int puts (const char* c) {
	fprintf(stdout, "[injector.so] Injected into host process\n");
	scan_pages();
	//print_pages();
	scan_for_signature(7570041587002597, 0x6ca); // 0x425
}
