#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "supp.h"

char mnebuf[32];
char dtabuf[96];
char adrbuf[64];


char *itostr(long integer)
{
	static char buf[16];

	sprintf(buf,"%ld",integer);
	return buf;
}

char *itohex(unsigned long integer, unsigned long len)
{
	static char buf[16];
	static char fmtbuf[] = "%04.4lx";

	fmtbuf[2] = len + '0';
	fmtbuf[4] = len + '0';
	sprintf(buf,fmtbuf,integer);
	return buf;
}

void mnecat(const char *buf)
{
	static unsigned long cnt;
	char *dst;
	unsigned char c;

	dst = &mnebuf[ mnebuf[0] ? cnt : 0 ];

	do
	{
		c = *buf++;
		*dst++ = c;
	}
	while (c);

	cnt = dst - &mnebuf[0] - 1;
}

void dtacat(const char *buf)
{
	static unsigned long cnt;
	char *dst;
	unsigned char c;

	dst = &dtabuf[ dtabuf[0] ? cnt : 0 ];

	do
	{
		c = *buf++;
		*dst++ = c;
	}
	while (c);

	cnt = dst - &dtabuf[0] - 1;
}

void adrcat(const char *buf)
{
	static unsigned long cnt;
	char *dst;
	unsigned char c;

	dst = &adrbuf[ adrbuf[0] ? cnt : 0 ];

	do
	{
		c = *buf++;
		*dst++ = c;
	}
	while (c);

	cnt = dst - &adrbuf[0] - 1;
}

char *argopt(int argc, char **argv, const char *foo, int *nextarg, char *option)
{
	char *odata;

	odata = 0;

	if (argc > *nextarg)
	{
		char *p;

		p = argv[*nextarg];

		if (*p == '-')
		{
			*nextarg += 1;
			p++;

			*option = *p;
			odata = p + 1;
		}
	}

	return odata;
}

int stricmp(const char *str1, const char *str2)
{
  const unsigned char *us1 = (const unsigned char *)str1,
                      *us2 = (const unsigned char *)str2;

  while (tolower(*us1) == tolower(*us2++))
    if (*us1++ == '\0')
      return 0;
  return (tolower(*us1) - tolower(*--us2));
}

int strnicmp(const char *str1, const char *str2, size_t n)
{
  if (str1==NULL || str2==NULL)
    return 0;

  if (n) {
    const unsigned char *us1 = (const unsigned char *)str1,
                        *us2 = (const unsigned char *)str2;

    do {
      if (tolower(*us1) != tolower(*us2++))
        return tolower(*us1) - tolower(*--us2);
      if (*us1++ == '\0')
        break;
    }
    while (--n != 0);
  }
  return 0;
}

int stccpy(char *p, const char *q, size_t n)
{
  char *t = p;

  while ((*p++ = *q++) && --n > 0);
  p[-1] = '\0';
  return p - t;
}

int stcd_l(const char *p, LONG *val)
{
  if (p) {
    if (*p=='+' || *p=='-' || (*p>='0' && *p<='9')) {
      char *p2;

      *val = (LONG)strtol(p, &p2, 10);
      return p2 - p;
    }
  }
  *val = 0;
  return 0;
}

int stch_l(const char *p, LONG *val)
{
  if (p) {
    if (*p=='+' || *p=='-' || isxdigit((unsigned char)*p)) {
      char *p2;

      *val = (LONG)strtol(p, &p2, 16);
      return p2 - p;
    }
  }
  *val = 0;
  return 0;
}

char *strupr(char *p)
{
  char *ret = p;

  while (*p) {
    if (islower(*p))
      *p = toupper(*p);
    p++;
  }
  return ret;
}

/* stripped down implementation, without support for drive, path and ext */
void strsfn(const char *file, char *drive, char *path, char *node, char *ext)
{
	const char *end = file + strlen(file);
	const char *p = file;
	extern void ExitPrg(const char *, ...);

	if (drive || path || ext)
		ExitPrg("strsfn called with non-NULL drive, path or ext!");

	while (*p && *p != ':')
		++p;
	if (*p++ == ':')
		file = p;
	p = end;
	while (p > file && p[-1] != '.' && p[-1] != '/')
		--p;
	if (p > file)
		end = p - 1;
	p = end;
	while (p > file && p[-1] != '/')
		--p;
	if (node) {
		if (end > p && end - p < FNSIZE) {
			memcpy(node, p, end - p);
			node += end - p;
		}
		*node = '\0';
	}
	end = p > file ? p - 1 : p;
}

void tmpfilename(char *name,size_t len)
{
#ifdef AMIGAOS
	sprintf(name,"T:ira%08lxlabels",FindTask(NULL));
#else
	strcpy(name,"L_XXXXXX");
	mktemp(name);
#endif
}

void delfile(const char *path)
{
	FILE *f;

	if ((f = fopen(path,"rb"))) {
		fclose(f);
		remove(path);
	}
}

void newlist(struct List *MyList)
{
	MyList->lh_TailPred = (struct Node *)MyList;
	MyList->lh_Tail = (struct Node *)NULL;
	MyList->lh_Head = (struct Node *)&MyList->lh_Tail;
}

struct Node *remhead(struct List *MyList)
{
	struct Node *RemovedNode;

	if ((RemovedNode = MyList->lh_Head)->ln_Succ) {
		MyList->lh_Head = RemovedNode->ln_Succ;
		MyList->lh_Head->ln_Pred = (struct Node *)&MyList->lh_Head;
		return RemovedNode;
	}
	else
		return NULL;
}

void addtail(struct List *MyList, struct Node *MyNode)
{
	struct Node *OldPredNode;

	OldPredNode = MyList->lh_TailPred;
	MyNode->ln_Succ = (struct Node *)&MyList->lh_Tail;
	MyNode->ln_Pred = OldPredNode;
	OldPredNode->ln_Succ = MyNode;
	MyList->lh_TailPred = MyNode;
}

UWORD be16(void *buf)
{
	UBYTE *p = buf;

	return (((UWORD)p[0]) << 8) | (UWORD)p[1];
}

ULONG be32(void *buf)
{
	UBYTE *p = buf;

	return (((ULONG)p[0]) << 24) | (((ULONG)p[1]) << 16) |
		(((ULONG)p[2]) << 8) | (ULONG)p[3];
}

void wbe32(void *buf,ULONG v)
{
	UBYTE *p = buf;

	*p++ = (UBYTE)(v>>24);
	*p++ = (UBYTE)(v>>16);
	*p++ = (UBYTE)(v>>8);
	*p = (UBYTE)v;
}

ULONG readbe32(FILE *f)
{
	ULONG d;

	if (fread(&d,sizeof(ULONG),1,f) == 1)
		return be32(&d);
	return 0;
}
