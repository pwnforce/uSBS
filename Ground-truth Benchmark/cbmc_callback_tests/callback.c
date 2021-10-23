#include<stdio.h>
#include<string.h>

typedef void (*my_callback)(char *string); // define the type of the callback function

void register_callback(my_callback cb); // function used to register the callback

/*
struct event_cb { // struct to store callback and other things
    my_callback cb;
};

struct event_cb *callback; // instantiate the struct
*/

static my_callback callb = 0;

void print(char *string) {
	__CPROVER_assert(0, "postcondition");
	printf("%s\n", string);
}

void register_callback(my_callback cb) {
	//callback->cb = cb;
	callb = cb;
}

int main() {


	printf("hi\n");
	my_callback cc = print;
	register_callback(cc);

	char s[3];
	s[0] = nondet_char(); //getchar();
	s[1] = nondet_char(); //getchar();
	s[2] = '\0';
	if(strcmp(s, "lo") == 0) {
		//assert(0);
		//__CPROVER_assert(0, "postcondition");
		//callback->cb(s);
		callb(s);
		//printf("%s\n", s);
	} else {
		printf("NONE\n");
	}
}

