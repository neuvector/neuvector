#define NSUTS    0
#define NSIPC    1
#define NSUSER   2
#define NSPID    3
#define NSNET    4
#define NSCGROUP 5

#define NS_COUNT 6

int nsget(const char *mntns, const char *filepath, int bin, int start, int len);
int nsrun(const char *mntns, const char **nss, const char *script, int bin, int from_stdin);
int nsexec(const char *mntns, const char **nss, char *const *cmd);
int nsexist(const char *mntns, const char *file);
