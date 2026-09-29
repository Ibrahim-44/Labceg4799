#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

int main() {
    uid_t ruid, euid, suid;

    // Vérifier les UIDs AVANT abandon
    getresuid(&ruid, &euid, &suid);
    printf("AVANT abandon: ruid=%d euid=%d suid=%d\n", ruid, euid, suid);

    // Abandon DEFINITIF du privilège (pas réversible)
    if (setresuid(ruid, ruid, ruid) != 0) {
        perror("setresuid");
        return 1;
    }

    // Vérifier APRÈS abandon
    getresuid(&ruid, &euid, &suid);
    printf("APRES abandon: ruid=%d euid=%d suid=%d\n", ruid, euid, suid);

    // Tenter une réélévation — doit échouer
    if (setresuid(0, 0, 0) == 0) {
        printf("DANGER: réélévation possible!\n");
    } else {
        printf("OK: réélévation impossible, privilège bien abandonné\n");
    }

    // Invoquer commande externe APRES abandon
    char *env[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };
    char *args[] = { "/bin/ls", "/tmp", NULL };
    execve("/bin/ls", args, env);
    perror("execve");
    return 1;
}
