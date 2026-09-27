/*
 * Teaching fixture: simplified heap use-after-free lab.
 * Local only. Not a full CTF challenge.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct note {
    char *data;
};

struct note *notes[4];

void menu(void) {
    puts("1. alloc  2. free  3. show  4. edit  5. quit");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    char secret[] = "flag{heap_uaf_lab}";
    (void)secret;
    int choice, idx;
    size_t n;
    menu();
    while (1) {
        printf("> ");
        if (scanf("%d", &choice) != 1) break;
        if (choice == 5) break;
        if (choice == 1) {
            printf("idx: "); scanf("%d", &idx);
            if (idx < 0 || idx > 3) continue;
            notes[idx] = malloc(sizeof(struct note));
            notes[idx]->data = malloc(0x30);
            printf("data: ");
            scanf("%47s", notes[idx]->data);
        } else if (choice == 2) {
            printf("idx: "); scanf("%d", &idx);
            if (idx < 0 || idx > 3 || !notes[idx]) continue;
            free(notes[idx]->data);
            free(notes[idx]);
            /* intentional UAF: pointer not nulled */
        } else if (choice == 3) {
            printf("idx: "); scanf("%d", &idx);
            if (idx < 0 || idx > 3 || !notes[idx]) continue;
            printf("%s\n", notes[idx]->data);
        } else if (choice == 4) {
            printf("idx: "); scanf("%d", &idx);
            if (idx < 0 || idx > 3 || !notes[idx]) continue;
            printf("data: ");
            scanf("%47s", notes[idx]->data);
        }
    }
    return 0;
}
