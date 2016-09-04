#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "polarssl/sha2.h"

int main(int argc, char **argv)
{
	int argi;
	int ret=0, hashi, i;
	unsigned int cmpoff = 0, calcoff = 0, blksz = 0;
	unsigned int cur_blksz = 0;
	int cmpoff_set = 0,  calcoff_set = 0, blksz_set = 0;
	FILE *f;

	unsigned char calchash[32];
	unsigned char cmphash[32];
	unsigned char *buf;

	memset(calchash, 0, 32);
	memset(cmphash, 0, 32);

	if(argc==2)
	{
		ret = sha2_file(argv[1], calchash, 0);
		if(ret)return ret;

		printf("%s SHA256 hash: ", argv[1]);
		for(hashi=0; hashi<32; hashi++)printf("%02x", calchash[hashi]);
		printf("\n");
		
		return 0;
	}

	for(argi=2; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--cmpoff=", 9)==0)
		{
			sscanf(&argv[argi][9], "%x", &cmpoff);
			cmpoff_set = 1;
		}
		if(strncmp(argv[argi], "--calcoff=", 10)==0)
		{
			sscanf(&argv[argi][10], "%x", &calcoff);
			calcoff_set = 1;
		}
		if(strncmp(argv[argi], "--blksz=", 8)==0)
		{
			sscanf(&argv[argi][8], "%x", &blksz);
			blksz_set = 1;
		}
	}

	if(!calcoff_set || !blksz_set)return 0;

	f = fopen(argv[1], "rb");
	if(f==NULL)
	{
		printf("failed to open file\n");
		return 0;
	}

	if(cmpoff_set)
	{
		fseek(f, cmpoff, SEEK_SET);
		fread(cmphash, 1, 32, f);

		printf("cmp SHA256 hash: ");
		for(hashi=0; hashi<32; hashi++)printf("%02x", cmphash[hashi]);
		printf("\n");
	}

	buf = (unsigned char*)malloc(blksz);
	if(buf==NULL)
	{
		printf("failed to alloc mem\n");
		fclose(f);
		return 0;
	}

	fseek(f, calcoff, SEEK_SET);
	fread(buf, 1, blksz, f);
	fclose(f);

	if(!cmpoff_set)
	{
		sha2(buf, blksz, calchash, 0);

		printf("calchash @ %x sz %x SHA256 hash: ", calcoff, blksz);
		for(hashi=0; hashi<32; hashi++)printf("%02x", calchash[hashi]);
		printf("\n");
	}
	else
	{
		for(i=0; i<blksz-1; i++)
		{
			printf("pos: %x\n", i);

			cur_blksz = blksz - i;
			while(cur_blksz)
			{
				sha2(&buf[i], cur_blksz, calchash, 0);
				if(memcmp(calchash, cmphash, 32)==0)
				{
					printf("win!\n");
					printf("calchash @ %x sz %x SHA256 hash: ", i, cur_blksz);
					for(hashi=0; hashi<32; hashi++)printf("%02x", calchash[hashi]);
					printf("\n");
					return 0;
				}
		
				cur_blksz--;
			}
		}
	}

	return 0;
}

