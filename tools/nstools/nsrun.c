#define _GNU_SOURCE
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <grp.h>

#include "nstools.h"
#define TOTAL_SCRIPT_SIZE (1024*200)

char script_buf[TOTAL_SCRIPT_SIZE];

static int read_script(const char *path) {
    FILE *filer;
    filer = fopen(path, "r");
    if (!filer) {
        return -1;
    }

    memset(script_buf, 0, TOTAL_SCRIPT_SIZE);
    int file_len = fread(script_buf, 1, TOTAL_SCRIPT_SIZE, filer);
    if (file_len <= 0) {
        fclose(filer);
        return -1;
    }
    fclose(filer);

    return 0;
}

int nsrun(const char *mntns, const char **nss, const char *script, int bin, int from_stdin)
{
    int ret, i;

    if (!from_stdin && script == NULL) {
        fprintf(stderr, "Need to provide script either from sdtin or file\n");
        return -1;
    }

    for (i=0; i<NS_COUNT; i++) {
        if (nss[i] != NULL) {
            int nsfd = open(nss[i], O_RDONLY);
            if (nsfd == -1) {
                if (i==NSCGROUP){
                    continue;
                }
                fprintf(stderr, "Failed to open namespace: %s\n", nss[i]);
                return -1;
            }

            ret = setns(nsfd, 0);
            if (ret == -1) {
                fprintf(stderr, "Failed to set %s namespace: %s\n", nss[i],strerror(errno));
                close(nsfd);
                return -1;
            }
            close(nsfd);
        }
    }

    if (from_stdin) {
        char *line = NULL;
        size_t len = 0;
        ssize_t nread;
        char *p = script_buf;

        while ((nread = getline(&line, &len, stdin)) > 0) {
            if ((p + nread) > (script_buf + TOTAL_SCRIPT_SIZE)) {
                fprintf(stderr, "Script buffer overflow\n");
                return -1;
            }
            memcpy(p, line, nread);
            p += nread;
        }
        *p = 0;
        free(line);
    } else if (bin == 1) {
        int len = strlen(script);
        if (len >= sizeof(script_buf)) {
            fprintf(stderr, "Path too long: %s\n", script);
            return -1;
        }

        // Remove ""
        if (script[0] == '"') {
            strncpy(script_buf, script + 1, sizeof(script_buf));
            script_buf[len - 2] = '\0';
        } else {
            strncpy(script_buf, script, sizeof(script_buf));
            script_buf[len] = '\0';
        }
    } else if (script != NULL) {
        ret = read_script(script);
        if (ret == -1) {
            fprintf(stderr, "Failed to read script: %s\n", script);
            return -1;
        }
    }

    if (mntns != NULL) {
        int fd = open(mntns, O_RDONLY);
        if (fd == -1) {
            perror("Failed to open host MNT namespace\n");
            return -1;
        }

        ret = setns(fd, 0);
        if (ret == -1) {
            fprintf(stderr, "Failed to set MNT namespace: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        close(fd);
    }

#define ERR_SCRIPT_NOT_RUN 2
    ret = WEXITSTATUS(system(script_buf));
    if (ret == ERR_SCRIPT_NOT_RUN) {
        //fprintf(stderr, "Script did not run\n");
        return ERR_SCRIPT_NOT_RUN;
    } else if (ret != 0) {
        //fprintf(stderr, "Failed to run script: ret=%d\n", ret);
        return -1;
    }
    return 0;
}

int nsexist(const char *mntns, const char *file) {
    int ret;

    if (mntns != NULL) {
        int fd = open(mntns, O_RDONLY);
        if (fd == -1) {
            perror("Failed to open host MNT namespace\n");
            return -1;
        }

        ret = setns(fd, 0);
        if (ret == -1) {
            fprintf(stderr, "Failed to set MNT namespace: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        close(fd);
    }

    int n = snprintf(script_buf, sizeof(script_buf), "which %s", file);
    if (n > sizeof(script_buf)) {
        fprintf(stderr, "Filename too long\n");
        return -1;
    }

    ret = WEXITSTATUS(system(script_buf));
    if (ret == ERR_SCRIPT_NOT_RUN) {
        fprintf(stderr, "Script did not run\n");
        return ERR_SCRIPT_NOT_RUN;
    } else if (ret != 0) {
        fprintf(stderr, "Failed to run script: ret=%d\n", ret);
        return -1;
    }
    return 0;
}
