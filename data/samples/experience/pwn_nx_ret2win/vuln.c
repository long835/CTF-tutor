
#include <stdio.h>
#include <string.h>
/* NX enabled (non-executable stack via default modern gcc);
 * teaching goal: ret2win, not shellcode. */
void win(void) {
    puts("flag{nx_ret2win_lab}");
}
void vuln(void) {
    char buf[48];
    printf("data: ");
    gets(buf);
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
