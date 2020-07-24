#include <stdio.h>
#include <stdlib.h>

#define BUF_SIZE 1000

int main() {
	FILE *fptr;
	unsigned char buffer[BUF_SIZE];

	fptr = fopen("txt", "rb");
	if(fptr == NULL) {
		printf("ERROR\n");
		exit(1);
	}
	
	/*fread(buffer, sizeof(buffer), 1, fptr);
	for(int i = 0; i < BUF_SIZE; i++) {
		if(i % 10 == 0) printf("\n");
		printf("%x ", buffer[i]);
	}
	*/
	fseek(fptr,4,0xFED30000);
	char ch;
	while(!feof(fptr)) {
		printf("%u", ch);
	}
	fclose(fptr);
	printf("Hello World??\n");
	
	return 0;
}
