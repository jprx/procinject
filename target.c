#include <stdio.h>

#define __FLAG__ "sigpwny{big_preload_energy}"

int find_me_you_wont (void) {
	for (int i = 0; i < 1; i++) {
		fprintf(stdout, "WINNER WINNER!!! %s\n", __FLAG__);
	}
}

int findme2 (int a) {
	return a;
}

int main () {
	puts("Hey kids");
	printf("findme2 says: %d\n", findme2(69));
	return 0;
}
