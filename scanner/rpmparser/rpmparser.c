
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>    
#include <netinet/in.h>
#include "db.h"
#include "rpmtypes.h"

// \ingroup header
 
const unsigned char rpm_header_magic[8] = {
	0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
};

enum headerFlags_e {
    HEADERFLAG_SORTED    = (1 << 0), //!< Are header entries sorted? 
    HEADERFLAG_ALLOCATED = (1 << 1), //!< Is 1st header region allocated? 
    HEADERFLAG_LEGACY    = (1 << 2), //!< Header came from legacy source? 
    HEADERFLAG_DEBUG     = (1 << 3), //!< Debug this header? 
};

typedef rpmFlags headerFlags;

enum headerImportFlags_e {
    HEADERIMPORT_COPY		= (1 << 0), // Make copy of blob on import? 
    HEADERIMPORT_FAST		= (1 << 1), // Faster but less safe? 
};

typedef rpmFlags headerImportFlags;

//void printdata(void * data, int len)
//{
//    int i;
//    unsigned char * p = ( unsigned char *) data;
//
//    for (i=0 ;i<len; i+=2) {
//        printf("%02x%02x ", p[0], p[1]); 
//        if (((i/2+1) % 16) == 0) {
//            printf("\n"); 
//        }
//        p+=2;
//    }
//    printf("\n"); 
//}

typedef struct entryInfo_s * entryInfo;
struct entryInfo_s {
    rpm_tag_t tag;		//!< Tag identifier. 
    rpm_tagtype_t type;		//!< Tag data type. 
    int32_t offset;		//!< Offset into data segment (ondisk only). 
    rpm_count_t count;		//!< Number of tag elements. 
};

typedef struct indexEntry_s * indexEntry;
struct indexEntry_s {
    struct entryInfo_s info;	//!< Description of tag data. 
    rpm_data_t data; 		//!< Location of tag data. 
    int length;			//!< No. bytes of data. 
    int rdlen;			//!< No. bytes of data in region. 
};

typedef struct headerToken_s * Header;
struct headerToken_s {
    void * blob;		//!< Header region blob. 
    indexEntry index;		//!< Array of tags. 
    int indexUsed;		//!< Current size of tag array. 
    int indexAlloced;		//!< Allocated size of tag array. 
    unsigned int instance;	//!< Rpmdb instance (offset) 
    headerFlags flags;
    int nrefs;			//!< Reference count. 
};

#define MAX_RPM_STRING_LEN  128
typedef struct packageInfo_  PackageInfo;
struct packageInfo_ {
    char name[MAX_RPM_STRING_LEN];
    char version[MAX_RPM_STRING_LEN];
    char release[MAX_RPM_STRING_LEN];
    int  epoch;
};

static inline int32_t rpmStrLen(char * s, int32_t len) {
    int i;
    for (i = 0; i < len; i++) {
        if (s[i] == 0) { 
            break;
        }
    }

    if (i < len) {
        return i;
    } else {
        return MAX_RPM_STRING_LEN;
    }
}

static inline void rpmStrCopy(char * d, char * s, int32_t len) {
    if (rpmStrLen(s, len) >= MAX_RPM_STRING_LEN) {
        return;
    } else {
        strcpy(d, s);
    }
}

int getPackageHeader(void * blob, unsigned int bsize, PackageInfo * pkg)
{
    const int32_t * ei = (int32_t *) blob;
    int32_t il = ntohl(ei[0]);		// index length 
    int32_t dl = ntohl(ei[1]);		// data length 
    entryInfo pe;
    unsigned char * dataStart;
    unsigned char * dataEnd;
    int i;
    pe = (entryInfo) &ei[2];
    dataStart = (unsigned char *) (pe + il);
    dataEnd = dataStart + dl;
    int32_t     left;
    int32_t     offset;

    unsigned int pvlen = sizeof(il) + sizeof(dl) + (il * sizeof(struct entryInfo_s)) + dl;
    
    if (bsize && bsize != pvlen) {
        return 0;
    }
    for(i=0; i<il; i++) {
        offset  = htonl(pe->offset);
        left    = il - offset;
        if ((dataStart + offset) >= dataEnd) {
            return 0;
        }

        if (htonl(pe->tag) == RPMTAG_NAME && htonl(pe->type) == RPM_STRING_TYPE) {

            rpmStrCopy(pkg->name, (char*)(dataStart + offset), left);
        } else if (htonl(pe->tag) == RPMTAG_VERSION && htonl(pe->type) == RPM_STRING_TYPE) {

            rpmStrCopy(pkg->version, (char*)(dataStart + offset), left);
        } else if (htonl(pe->tag) == RPMTAG_RELEASE && htonl(pe->type) == RPM_STRING_TYPE) {

            rpmStrCopy(pkg->release, (char*)(dataStart + offset), left);
        } else if (htonl(pe->tag) == RPMTAG_EPOCH && htonl(pe->type) == RPM_INT32_TYPE) {

            pkg->epoch = htonl(*(uint64_t *)(dataStart + offset));
        }
        pe ++;
    }

    if (strlen(pkg->name) == 0 || strlen(pkg->version) == 0) {
        return 0;
    }

    return 1;
}

int main(int argc, char *argv[])
{
	DB *dbp;
	int ret;
    DBTYPE type;
    DBC *cursorp;
    DBT key;
    DBT data;

    if (argc < 2) {
        return 0;
    }

	ret = db_create(&dbp, NULL, 0);
	if (ret != 0) {
		printf("db_create: %s\n", db_strerror(ret));
        return -1;
		
	}

	ret = dbp->open(dbp, NULL, argv[1], NULL, DB_UNKNOWN, DB_RDONLY, 0664);
	if (ret != 0) {
		printf("open err\n");
		dbp->err(dbp, ret, "%s", argv[1]);
        return -1;
	}

    ret = dbp->get_type(dbp,&type);
    if (ret != 0 || type != DB_HASH) {
		printf("get type err\n");
		dbp->err(dbp, ret, "%s", argv[1]);
        return -1;
    }

    ret = dbp->cursor(dbp,  NULL, &cursorp, 0);
    if (ret != 0) {
		printf("get cursor err\n");
		dbp->err(dbp, ret, "%s", argv[1]);
        return -1;
    }
    PackageInfo pkg;

    do {
        memset(&data, 0, sizeof(data));
        memset(&key, 0, sizeof(key));
        memset(&pkg, 0, sizeof(pkg));

        ret = cursorp->c_get(cursorp, &key, &data, DB_NEXT);
        if (ret != 0) { 
            break;
        }
        if (getPackageHeader(data.data, data.size, &pkg)) {
            if (pkg.epoch==0) {
                printf("%s (none):%s-%s\n", pkg.name, pkg.version, pkg.release);
            } else {
                printf("%s %d:%s-%s\n", pkg.name, pkg.epoch, pkg.version, pkg.release);
            }
        }
    }while(ret == 0);

    return 0;

}
