
#include <stdio.h>
#include <string.h>
/* Stack canary ON. Format string leak then overflow. */
void win(void) { puts("flag{canary_fmt_lab}"); }
void vuln(void) {
    char buf[64];
    printf("echo: ");
    fgets(buf, sizeof(buf), stdin);
    printf(buf); /* format string */
    printf("again: ");
    gets(buf);   /* overflow after leak */
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
