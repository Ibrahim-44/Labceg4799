#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    printf("UID effectif: %d\n", geteuid());
    system("ls");   // commande SANS chemin absolu — la faille
    return 0;
}
