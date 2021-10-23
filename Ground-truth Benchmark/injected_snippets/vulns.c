void off_by_one() {
	int off_by_one_len = 20;
	char off_by_one[off_by_one_len];
	for (int counter_off_by_one = 0; counter_off_by_one < off_by_one_len - 1; counter_off_by_one++) {
		off_by_one[counter_off_by_one] = 'a';
	}
	off_by_one[off_by_one_len - 1] = '\0';
	char dst[off_by_one_len - 1];
	sprintf((char*)dst, "%s", (char*)off_by_one); // here we go after dst by 1 char
}

void bof() {

	int bof_len = 1024;
	char dst[bof_len - 1000];
	char bof[bof_len];
	for (int counter_bof = 0; counter_bof < bof_len - 1; counter_bof++) {
		if (counter_bof < 10) {
			bof[counter_bof] = 'a';
		} else if (counter_bof < 20) {
			bof[counter_bof] = 'a';
		} else 	if (counter_bof < 30) {
			bof[counter_bof] = 'a';
		} else 	if (counter_bof < 40) {
			bof[counter_bof] = 'a';
		} else 	if (counter_bof < 50) {
			bof[counter_bof] = 'a';
		} else 	if (counter_bof < 60) {
			bof[counter_bof] = 'a';
		} else 	if (counter_bof < 70) {
			if (counter_bof == 60) {// 4 python3 -m hal_fuzz.harness -d -t -b 134222826 -c ./test/stm32_udp_echo_server.yml ./test/inputs/crash/UDP_Echo_Server_Client_first_char.pcapng.input
				bof[counter_bof] = 'b';
			} else if (counter_bof == 61) {// 3
				bof[counter_bof] = 'c';
			} else if (counter_bof == 62) {// 2
				bof[counter_bof] = 'd';
			} else if (counter_bof == 63) { // 1
				bof[counter_bof] = 'e';
			} else {
				bof[counter_bof] = 'p';
			}
		} else 	if (counter_bof < 81) {
			bof[counter_bof] = 'z';
		} else 	if (counter_bof < 90) {
			bof[counter_bof] = 'z';
		} else 	if (counter_bof < 100) {
			bof[counter_bof] = 'z';
		} else 	if (counter_bof < 110) {
			bof[counter_bof] = 'z';
		} else {
			bof[counter_bof] = 'z';
		}
	}
	bof[bof_len - 1] = '\0';

	//char bof[] = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0";

	sprintf((char*)dst, "%s", (char*)bof); // here we go after dst by 21 char
	//memcpy(dst,bof,0x400);
}

void double_free() {
	// useless code to make it compile the function
	int off_by_one_len = 7;
	char off_by_one[off_by_one_len];
	for (int counter_off_by_one = 0; counter_off_by_one < off_by_one_len - 1; counter_off_by_one++) {
		off_by_one[counter_off_by_one] = 'a';
	}
	off_by_one[off_by_one_len - 1] = '\0';

	char* a = malloc(10);     // 0xa04010
	char* b = malloc(10);     // 0xa04030
	char* c = malloc(10);     // 0xa04050

	sprintf((char*)a, "%s", (char*)off_by_one);
	sprintf((char*)b, "%s", (char*)off_by_one);
	sprintf((char*)c, "%s", (char*)off_by_one);


	free(a);
	free(b);  // To bypass "double free or corruption (fasttop)" check
	free(a);  // Double Free !!

	char* d = malloc(10);     // 0xa04010
	char* e = malloc(10);     // 0xa04030
	char* f = malloc(10);     // 0xa04010   - Same as 'd' !

	sprintf((char*)d, "%s", (char*)off_by_one);
	sprintf((char*)e, "%s", (char*)off_by_one);
	sprintf((char*)f, "%s", (char*)off_by_one);

	free(c);
	free(d);
	free(e);
	free(f);


	char dst[off_by_one_len];
	sprintf((char*)dst, "%s", (char*)off_by_one); // NO BUGS HERE, just useless code
}

typedef struct name {
    int mynumber;
    int (*func)(char *str);
} NAME;

int myprint(char *str) { return (int) str[0] + 10; }
int halfmynumber() { return 7 / 2; }

int uaf() {
    // USE AFTER FREE VULN

	int var1;
	int var2;
	int var3;

    NAME *a;
    a = (NAME *)malloc(sizeof(struct name));
    a->func = myprint;
    a->mynumber = 33;
    var1 = a->func("this is my function");

    // free without modify
    free(a);
    var1 = a->func("I can also use it"); // I'm still using it after a free and doesn't crash

    // free with modify
    a->func = halfmynumber;
    var2 = a->func("this is my function"); // I'm still using it after a free and a pointer modification and doesn't crash

    // set NULL
    a = NULL; // Now I make it crash
    //printf("this pogram will crash...\n");
    var3 = a->func("can not be printed...");

    return var1 + var2 + var3;
}
