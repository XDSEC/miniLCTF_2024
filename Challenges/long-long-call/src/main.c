#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint8_t enc[] = {187, 191, 185, 190, 195, 204, 206, 220, 158, 143, 157,
                 155, 167, 140, 215, 149, 176, 173, 189, 180, 136, 175,
                 146, 208, 207, 161, 163, 146, 183, 180, 201, 158, 148,
                 167, 174, 240, 161, 153, 192, 227, 180, 180, 191, 227};

void anti_debug() __attribute__((constructor));

void anti_debug() {
    char chunk[200];

    if (getenv("LD_PRELOAD")) {
        puts("hacker XD:");
        exit(1);
    }

    FILE *fp = fopen("/proc/self/status", "r");
    char buf[0x100];
    char *ptr = buf;
    while (fgets(ptr, 0x100, fp)) {
        if (strstr(ptr, "TracerPid")) {
            int tracepid = 0;
            tracepid = atoi((char *)ptr + strlen(ptr) - 3);
            if (tracepid != 0) {
                puts("hacker XD:");
                exit(1);
            }
        }
    }
}

void encrypt(uint8_t *input) {
    char chunk[200];
    for (int i = 0; i < 44; i += 2) {
        uint8_t x = input[i] + input[i + 1];
        input[i] ^= x;
        input[i + 1] ^= x;
    }
}

void check(uint8_t *input) {
    uint8_t chunk[200];
    for (int i = 0; i < 44; i++) {
        puts("checking...");
        sleep(2 * i);
        if (input[i] != enc[i]) {
            puts("Wrong!");
            exit(1);
        }
    }
    puts("Right");
    exit(0);
}

int main() {
    // miniLCTF{just_s1mple_x0r_1n_lon9_l0ng_c@ll!}

    uint8_t input[50];

    puts("input your flag:");
    scanf("%44s", input);
    puts("ok, let's go");
    encrypt(input);
    check(input);

    return 0;
}
