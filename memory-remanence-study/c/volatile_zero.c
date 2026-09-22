#include <string.h>

void use_key(unsigned char *key);

void derive_and_wipe_volatile(void) {
    unsigned char key[32];

    for (int i = 0; i < 32; i++) key[i] = i;

    use_key(key);

    // volatile pointer: the compiler must treat every write through this
    // pointer as having an observable effect, even though nothing reads
    // the values afterward — that's the definition of volatile semantics.
    volatile unsigned char *p = key;
    for (int i = 0; i < 32; i++) p[i] = 0;
}