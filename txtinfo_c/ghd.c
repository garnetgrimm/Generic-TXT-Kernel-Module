/* usage: hexdump <file-in> [file-out] */

#include <stdio.h>

#define TXT_REGISTER 0xfed30000
#define CHUNK 16

int main(int argc, char const *argv[]) {
    FILE *fp_in;
    FILE *fp_out;
    unsigned char buf[CHUNK];
    size_t nread;
    int i, c, npos;

    if (!(fp_in = fopen("/dev/mem", "r"))) {
        printf("error opening /dev/mem  \n");
        return 0;
    }


    //fp_out = (argc == 3 ? hexdump_open(argv[2], "w") : stdout);
    fp_out = stdout;
    
    npos = TXT_REGISTER;
    fseek(fp_in, TXT_REGISTER, SEEK_SET);
 
    /* display hex data CHUNK bytes at a time */
    while ((nread = fread(buf, 1, sizeof buf, fp_in)) > 0) {
        fprintf(fp_out, "%04x: ", npos);
        npos += CHUNK;

        /* print hex values e.g. 3f 62 ec f0*/
        for (i = 0; i < CHUNK; i++)
            fprintf(fp_out, "%02x ", buf[i]);

        /* print ascii values e.g. ..A6..ó.j...D*/
        for (i = 0; i < CHUNK; i++) {
            c = buf[i];
            fprintf(fp_out, "%c", (c >= 33 && c <= 255 ? c : '.'));
        }
        fprintf(fp_out, "\n");
    }

    fclose(fp_in);

    return 0;
}
