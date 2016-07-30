#include "substrate.h"
#include <android/log.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <cstdlib>
#include "memcmp_hook.cy.h"
#include "base64.h"
#include <errno.h>

const char *workDir = "/data/local/tmp/";
MSConfig(MSFilterLibrary, "/system/lib/libc.so")

void get_process_name(const int pid, char *name)
{
	if (!name) return;
        
        sprintf (name, "/proc/%d/cmdline", pid);
        FILE* f = fopen (name, "r");
        if (f) {
                size_t size;
                size = fread (name, sizeof(char), 1024, f);
                if (size > 0) {
                        if('\n' == name[size-1])
                                name[size-1] = '\0';
                }
                fclose (f);
        }
}

void dump (const void *buf1, unsigned int len, const char *p_name)
{
	FILE *fp = NULL;
	char dump_name [256] = {0};

	unsigned int dlen = len*3;
	unsigned char *dst = (unsigned char*)malloc (dlen);
	memset(dst, 0x00, dlen);

	sprintf (dump_name, "%s%s_%d.dex", workDir, p_name, len);
	LOGD ("SHOOT dump name : %s", dump_name);
	if(NULL == (fp = fopen (dump_name, "wb"))) {
		LOGD ("FAULT error fopen [%s],[%s] ", dump_name, strerror (errno));
	} else {
		base64_encode (dst, &dlen, (unsigned char*)buf1, len);
		fwrite (dst, dlen, 1, fp);
	}
	free (dst);
	fclose (fp);
}

int (*OldMemcmp) (const void *buf1, const void *buf2, unsigned int count);
int NewMemcmp (const void *buf1, const void *buf2, unsigned int count)
{
        if (buf1 == NULL || buf2 == NULL) 
                return OldMemcmp (buf1, buf2, count);
        
	pid_t pid = getpid ();
	char p_name[256] = {0};
	get_process_name (pid, p_name);

	if (strncmp (p_name, "com.licai", 9) != 0)  //filter
                return OldMemcmp (buf1, buf2, count);
                

        LOGD ("SHOOT Package Name : %s", p_name);
        if (*(unsigned int*)buf1 == 0xA786564) { //dex\n
                DexHeader *pHeader = (DexHeader*)buf1;
                dump (buf1, pHeader->fileSize, p_name);
        }
	return OldMemcmp (buf1, buf2, count);
}

MSInitialize
{
	MSImageRef image;
	image = MSGetImageByName ("/system/lib/libc.so");
	if (image != NULL) {
		LOGD ("cydia init, good luck");
		void *dexload = MSFindSymbol (image, "memcmp");
		if(dexload == NULL)  {
			LOGD ("FAULT error find memcmp");
		} else {
			MSHookFunction (dexload, (void*)&NewMemcmp, (void **)&OldMemcmp);
		}

	} else {
		LOGD ("FAULT libc.so not found");
	}
}

