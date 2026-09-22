#include <string.h>

void use_key(unsigned char *key); // opaque external function — compiler
                                    // cannot see or inline this, so it
                                    // cannot prove the buffer is unused
                                    // after use_key() returns

void derive_and_wipe(void) {
    unsigned char key[32];

    // "derive" a key (stand-in — in your real code this is Argon2id)
    for (int i = 0; i < 32; i++) key[i] = i;

    use_key(key);

    // naive manual zeroing — this is the line we expect to vanish
    for (int i = 0; i < 32; i++) key[i] = 0;
}