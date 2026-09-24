/*
 * Teaching fixture only — intentionally vulnerable.
 * Not a contest challenge. Local lab use.
 */
#include <stdio.h>
#include <string.h>

void win(void) {
    puts("win: you redirected control flow (lab marker)");
}

void vuln(void) {
    char buf[32];
    printf("input: ");
    fflush(stdout);
    /* intentionally unbounded for teaching */
    gets(buf);
    printf("hello %s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
