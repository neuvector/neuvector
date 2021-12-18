#define _GNU_SOURCE
#include <stdint.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

//need max size to limit the output, or it will be too big for agent to handle
#define MAX_FILE_SIZE   (100 * 1024 * 1024) //100MB
#define IN_PAGE_SIZE    (3 * 1024)
#define OUT_PAGE_SIZE   (4 * 1024)

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};

static size_t base64_encode(const unsigned char *in_data,
                    unsigned char *out_data,
                    size_t input_length
                    ) {
    int i,j;
    size_t output_length = 4 * ((input_length + 2) / 3);

    for (i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)in_data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)in_data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)in_data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        out_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        out_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        out_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        out_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        out_data[output_length - 1 - i] = '=';

    return output_length;
}

static int encode_file(const char *path) {
    FILE *filer;
    filer = fopen(path, "r");
    if (!filer) {
        fprintf(stderr, "open file:%s error\n", path);
        return -1;
    }

    fseek(filer, 0, SEEK_END);
    int size = ftell(filer); 
    if(size <= 0 || size >= MAX_FILE_SIZE) {
        fclose(filer);
        fprintf(stderr, "read file len error, size=%d, path=%s\n", size, path);
        return 2;
    }
    unsigned char * in_buf = malloc(IN_PAGE_SIZE);
    unsigned char * out_buf = malloc(OUT_PAGE_SIZE+1);
    if(in_buf == NULL || out_buf == NULL) {
        fclose(filer);
        free(in_buf);
        free(out_buf);
        fprintf(stderr, "allocate memory error, path=%s\n", path);
        return -1;
    }
    fseek(filer, 0, SEEK_SET);
    int file_len;
    do {
        file_len = fread(in_buf, 1, IN_PAGE_SIZE, filer);
        if (file_len > 0) {
            size_t out_size = base64_encode(in_buf, out_buf, file_len);
            out_buf[out_size] = 0;
            printf("%s",out_buf);
        }
    } while (file_len > 0);

    fclose(filer);
    free(in_buf);
    free(out_buf);
    return 0;
}

static int read_txt_file(const char *path, int start, int limit) {
    FILE *filer;
    filer = fopen(path, "r");
    if (!filer) {
        fprintf(stderr, "open file:%s error\n", path);
        return -1;
    }
    fseek(filer, 0, SEEK_END);
    int size = ftell(filer);

    unsigned char * in_buf = malloc(OUT_PAGE_SIZE+1);
    if(in_buf == NULL) {
        fprintf(stderr, "allocate memory error, path=%s\n", path);
        fclose(filer);
        return -1;
    }

    if (start == -1) {
        //-1: the last bytes
        if (limit >= size) {
            fseek(filer, 0 , SEEK_SET);
        } else {
            fseek(filer, -limit, SEEK_END);
        }
    } else {
        if (start > size) {
            fprintf(stderr, "wrong start position, size=%d,start=%d\n", size, start);
            fclose(filer);
            free(in_buf);
            return -1;
        } else {
            fseek(filer, start , SEEK_SET);
        }
    }
    int file_len, count=0;
    do {
        file_len = fread(in_buf, 1, OUT_PAGE_SIZE, filer);
        if (file_len > 0) {
            printf("%s",in_buf);
            count += file_len;
            if (limit > 0 && count >= limit) {
                break;
            }
        }
    } while (file_len > 0);

    fclose(filer);
    free(in_buf);
    return 0;
}

int nsget(const char *mntns, const char *filepath, int bin, int start, int len) {
    int ret;

    // currently, the start and len only apply to text
    if (mntns == NULL || filepath == NULL) {
        return -1;
    }
    int fd = open(mntns, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open MNT namespace\n");
        return -1;
    }

    ret = setns(fd, 0);
    close(fd);
    if (ret == -1) {
        fprintf(stderr, "Failed to set MNT namespace: %s\n", strerror(errno));
        return -1;
    }

    if (bin) {
        ret = encode_file(filepath);
    } else {
        ret = read_txt_file(filepath, start, len);
    }

    return ret;
}
