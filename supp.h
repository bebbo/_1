/*
	Author   : Tim Ruehsen, Crisi, Frank Wille
   Project  : IRA  -  680x0 Interactive ReAssembler
	Part     : supp.h
   Purpose  : OS specific and Amiga compatibility defines
	Copyright: (C)1993-1995 Tim Ruehsen, (C)2009-2012 Frank Wille
*/

#ifndef SUPP_H
#define SUPP_H

#include <stdint.h>

#define FNSIZE 108

#ifdef AMIGAOS

#include <proto/exec.h>

#else

#define CONST const
#define STATIC static
#define TEXT char
#define VOID void
typedef char *STRPTR;
typedef const char *CONST_STRPTR;
typedef int8_t BYTE;
typedef uint8_t UBYTE;
typedef int16_t WORD;
typedef uint16_t UWORD;
typedef int32_t LONG;
typedef uint32_t ULONG;

#define NT_LIBRARY	9
#define NT_DEVICE	3
#define NT_RESOURCE	8

struct Node
{
    struct Node *ln_Succ;
    struct Node *ln_Pred;
    char        *ln_Name;
};

struct List
{
    struct Node *lh_Head;
    struct Node *lh_Tail;
    struct Node *lh_TailPred;
};

#endif /* AMIGAOS */


/******** prototypes *********/

#define lmovmem(x,y,a) memmove(y,x,(a)*sizeof(LONG))

void ExitPrg(CONST_STRPTR , ...);
char *itostr(long);
char *itohex(unsigned long, unsigned long);
void mnecat(const char *);
void adrcat(const char *);
void dtacat(const char *);
char *argopt(int , char **, const char *, int *, char *);
int stricmp(const char *, const char *);
int strnicmp(const char *, const char *, size_t);
int stccpy(char *, const char *, size_t);
int stcd_l(const char *, LONG *);
int stch_l(const char *, LONG *);
char *strupr(char *);
void strsfn(const char *, char *, char *, char *, char *);
void tmpfilename(char *,size_t);
void delfile(const char *);
void newlist(struct List *);
struct Node *remhead(struct List *);
void addtail(struct List *, struct Node *);
UWORD be16(void *);
ULONG be32(void *);
void wbe32(void *,ULONG);
ULONG readbe32(FILE *);

#endif /* SUPP_H */
