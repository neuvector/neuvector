#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "nstools.h"

int nsget(const char *mntns, const char *filepath, int bin, int start, int len);
int nsrun(const char *mntns, const char **nss, const char *script, int bin, int from_stdin);
int nsexist(const char *mntns, const char *file);


static void help(const char *prog)
{
    printf("%s: {action} \n", prog);
    printf("  h: help\n");
    printf("  a: action\n");
    printf("  m: mnt file\n");
    printf("  n: net file\n");
    printf("  f: file path\n");
    printf("  i: read script from stdin - run action\n");
    printf("  b: binary, base64 output, read the whole file - get action\n");
    printf("  s: start position(Mega byte),-1 is the last byte, default=0.only apply to text file - get action\n");
    printf("  l: Mega byte to read, default=0.only apply to text, if 0, read all text file - get action\n");
}

static int VerifyParentProcess(void) {
    struct stat sb;
    char path[256]={0};
    int nRet = 0;

    sprintf( path, "/proc/%d/exe",  getppid());
    if (lstat(path, &sb) != -1) {
        char *linkname = (char *) malloc( 256);
        if (linkname != NULL) {
            memset( linkname, 0, 256);
            ssize_t r = readlink( path, linkname, 256);
            if (r > 0) {
                if (strcmp("/usr/local/bin/agent", linkname) == 0 ||
                   strcmp("/usr/local/bin/controller", linkname) == 0 ||
                   strcmp("/usr/local/bin/pathWalker", linkname) == 0) {
                    nRet = 1;
                }
            }
        }

        if (linkname != NULL) {
            free( linkname);
        }
    }
    return nRet;
}

int main(int argc, char *argv[]) {
    int ret;
    char *act = NULL, *mntns = NULL, *filepath = NULL;
    int bin = 0, start = 0, len = 0, from_stdin = 0;
    int arg = 0;
    const char *nss[6]={NULL,NULL,NULL,NULL,NULL,NULL};

    if( 0==VerifyParentProcess()) {
        printf("\n====\n");   // invalid caller
        help(argv[0]);      // confuse users
        exit(-1);
    }

    if (argc < 2) {
        help(argv[0]);
        exit(-1);
    }

    act = argv[1];

    while (arg != -1) {
        arg = getopt(argc - 1, argv + 1, "ha:bm:t:c:u:p:n:g:if:s:l:");

        switch (arg) {
        case -1:
            break;
        case 'a':
            act = optarg;
            break;
        case 'm':
            mntns = optarg;
            break;
        case 't':
            nss[NSUTS] = optarg;
            break;
        case 'c':
            nss[NSIPC] = optarg;
            break;
        case 'u':
            nss[NSUSER] = optarg;
            break;
        case 'p':
            nss[NSPID] = optarg;
            break;
        case 'n':
            nss[NSNET] = optarg;
            break;
        case 'g':
            nss[NSCGROUP] = optarg;
            break;
        case 'f':
            filepath = optarg;
            break;

        // run action
        case 'i':
            from_stdin = 1;
            break;

        // run and get action
        case 'b':
            bin = 1;
            break;

        // get action
        case 's':
            start = atoi(optarg);
            break;
        case 'l':
            len = atoi(optarg);
            break;

        case 'h':
        default:
            help(argv[0]);
            exit(0);
        }
    }
    ret = 0;
    if (strcmp(act, "exist") == 0) {
        ret = nsexist(mntns, filepath);
    } else if (strcmp(act, "run") == 0) {
        ret = nsrun(mntns, nss, filepath, bin, from_stdin);
    } else if (strcmp(act, "get") == 0) {
        ret = nsget(mntns, filepath, bin, start, len);
    }

    return ret;
}
