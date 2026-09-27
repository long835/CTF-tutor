
#include <stdio.h>
#include <string.h>
/* Teaching: password compare; flag in binary */
int main(void) {
    char buf[64];
    const char *secret = "s3cret_lab";
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("password: ");
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    buf[strcspn(buf, "\n")] = 0;
    if (strcmp(buf, secret) == 0) {
        puts("flag{rev_password_lab}");
    } else {
        puts("nope");
    }
    return 0;
}
