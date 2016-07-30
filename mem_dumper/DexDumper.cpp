#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <limits.h>
#include "DexFile.h"
#include <sys/ptrace.h>

int get_clone_pid(int pid)
{
	int result = 0;
	char taskBuf [256] = {0};
	sprintf (taskBuf, "/proc/%d/task/", pid);

	DIR *df = opendir (taskBuf);
	struct dirent *v3, *v1;

	if (df) {
		while(1) {
			v3 = readdir(df);
			if (!v3) {
				break;
				perror("readdir");
			}
			v1 = v3;	
		}
	}

	if (v1) {
		closedir (df);
		result = atoi ((const char*)(v1->d_name));
	} 
	printf ("clone pid : %d\n", result);

	return result;

}

#define WORKDIR "/data/local/tmp/"

void dump_memory_region (FILE *p_mem, unsigned long addr, long length, int sPid, char *filter)
{
        FILE *fp = NULL;
        char dumpName[256] = {0};

        unsigned char *idx = NULL;
	unsigned char *buffer = (unsigned char*)malloc (1024000000);
	memset (buffer, 0x0, length+1);
        
	fseeko (p_mem, addr, SEEK_SET);
	fread (buffer, 1, length, p_mem);
	
	for (idx = buffer; idx < buffer + length; idx++) {
		if (idx[0] == 'd' && idx[1] == 'e' && idx[2] == 'x' && idx[3] == '\n') { //shoot dex\n
			DexHeader *pHeader = (DexHeader*)idx;
			if (pHeader->headerSize != 0x70) continue; //assert a correct header
                            
                        printf ("[FIND >>>] DEX's Location : [%p], @filter : [%s]\n", idx, filter);  
                        printf ("    [+] DEX's size : %d\n", pHeader->fileSize);

                        sprintf (dumpName, "%s%d_%d.dex", WORKDIR, sPid, pHeader->fileSize);				
                        if (NULL == (fp = fopen (dumpName, "wb"))) {
                                printf ("error fopen : %s\n", dumpName);
                                free (buffer);
                                return;
                        } else {
                                printf ("    [+] DUMP DEX TO [%s][<<<]\n\n", dumpName);
                                fwrite (idx, pHeader->fileSize, 1, fp);
                        }
				fclose (fp);
		}
	}
	free (buffer);
}

void dump_dexfile (int pid)
{
	char maps_name [128] = {0};
	sprintf (maps_name, "/proc/%d/maps", pid);
        FILE *p_maps = fopen (maps_name, "r");
        
        char mem_name[128] = {0};
        sprintf (mem_name, "/proc/%d/mem", pid);
        FILE *p_mem = fopen (mem_name, "r");	
	
	if (p_mem == NULL || p_maps == NULL) {
		perror ("fopen maps or mem failed")
		return;
	}
	char line [256];
	char filter [256] = {0};
	while (fgets (line, 256, p_maps) != NULL) {
		unsigned long start_addr;
		unsigned long end_addr;
		sscanf (line, "%08lx-%08lx%*s%*s%*s%*s %s", &start_addr, &end_addr, filter);
		if (strstr (filter, "/system/framework/") != 0 || 
                        strstr (filter, "classes.dex") != 0) // add some filter here
			continue;
		dump_memory_region (p_mem, start_addr, end_addr - start_addr, pid, filter);
	}
	fclose (p_maps);
	fclose (p_mem);
}

int main (int argc, char *argv[])
{
	int pid = atoi(argv[1]);	

	int clone_pid = get_clone_pid (pid);
	long p_result = ptrace (PTRACE_ATTACH, clone_pid, NULL, NULL);
	if (p_result < 0)
	{
		printf ("Unable to attach to the pid : %d\n", pid);
		return -1;
	}

	dump_dexfile (clone_pid);

	ptrace (PTRACE_CONT, clone_pid, NULL, NULL);
        ptrace (PTRACE_DETACH, clone_pid, NULL, NULL);

	return 0;
}
