#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("UID effectif avant: %d\n", geteuid());

    // Environnement contrôlé : liste blanche seulement
    char *env[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };

    // Chemin absolu, pas de system()
    char *args[] = { "/bin/ls", "/tmp", NULL };
    execve("/bin/ls", args, env);

    // Si execve échoue
    perror("execve");
    return 1;
}
