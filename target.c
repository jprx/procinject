#include <stdio.h>

int findme (int a) {
	return a;
}

int main () {
	puts("Printing all numbers 1 to 10!");
	for (int i = 1; i <= 10; i++) { printf("findme says: %d\n", findme(i)); }
	return 0;
}
