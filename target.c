#include <stdio.h>

#define __FLAG__ "sigpwny{big_preload_energy}"

int find_me_you_wont (void) {
	for (int i = 0; i < 1; i++) {
		fprintf(stdout, "WINNER WINNER!!! %s\n", __FLAG__);
	}
}

int findme (int a) {
	return a;
}

int main () {
	puts("Printing all numbers 1 to 10!");
	for (int i = 1; i <= 10; i++) { printf("findme says: %d\n", findme(i)); }
	return 0;
}
