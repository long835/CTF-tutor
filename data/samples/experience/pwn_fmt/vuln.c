/*
 * Teaching fixture: format-string leak lab. Local only.
 */
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[128];
    char secret[] = "flag{fmt_lab}";
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("echo: ");
    if (!fgets(buf, sizeof(buf), stdin))
        return 0;
    /* intentionally pass user buffer as format */
    printf(buf);
    return 0;
}
