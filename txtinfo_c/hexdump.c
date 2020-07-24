#include <stdio.h>

#define CHUNK 16
#define TXT_REGISTER 0xFED30000

int main(int argc, char const *argv[]) {
    FILE *fp_in;
    FILE *fp_out;
    unsigned char buf[CHUNK];
    size_t nread;
    int i, c, npos;
    int line;

    /* open the input file */
    FILE *fp_in;
    if (!(fp = fopen(path, mode))) {
        printf("error opening '%s'", path);
        return 1;
    }
    
    line = 0;
    npos = TXT_REGISTER;
    fseek(fp_in, npos, SEEK_SET);
    
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
