#include<stdio.h>
#include<string.h>

int main() {
	printf("hi\n");
	char s[3];
	s[0] = nondet_char(); //getchar();
	s[1] = nondet_char(); //getchar();
	s[2] = '\0';
	if(strcmp(s, "lo") == 0) {
		//assert(0);
		__CPROVER_assert(0, "postcondition");
		printf("%s\n", s);
	} else {
		printf("NONE\n");
	}
}
