
#include <stdio.h>
#include <string.h>
void win(void) {
    puts("flag{ret2win_lab}");
}
void vuln(void) {
    char buf[40];
    printf("name: ");
    gets(buf);
    printf("hi %s\n", buf);
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
