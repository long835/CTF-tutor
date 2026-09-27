
#include <stdio.h>
#include <string.h>
/* Decoy: binary mentions AES but bug is stack overflow */
char *hint = "AES-256-CBC config";
void win(void) { puts("flag{decoy_crypto_was_wrong}"); }
void vuln(void) {
    char buf[32];
    printf("config: ");
    gets(buf);
    printf("ok %s\n", buf);
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
