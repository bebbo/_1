/*
	Author   : Tim Ruehsen, Crisi, Frank Wille
   Project  : IRA  -  680x0 Interactive ReAssembler
	Part     : IRA.h
   Purpose  : Contains definitions for all IRA sources.
	Copyright: (C)1993-1995 Tim Ruehsen, (C)2009-2014 Frank Wille
*/

#ifndef IRA_H
#define IRA_H


#define VERSION     "2"
#define REVISION    "08"
#define BETA        0
#if BETA == 0
  #define IDSTRING1   ("\nIRA V%s.%s "__AMIGADATE__"\n" \
                       "(c)1993-95 Tim Ruehsen (SiliconSurfer/PHANTASM)\n" \
                       "(c)2009-2014 Frank Wille\n\n")
  #define IDSTRING2   ("; IRA V%s.%s "__AMIGADATE__" (c)1993-95 Tim Ruehsen, (c)2009-2014 Frank Wille\n\n")
#else
  #define IDSTRING1   ("\nIRA V%s.%sbeta "__AMIGADATE__"\n" \
                       "(c)1993-95 Tim Ruehsen (SiliconSurfer/PHANTASM)\n" \
                       "(c)2009-2014 Frank Wille\n\n")
  #define IDSTRING2   ("; IRA V%s.%sbeta "__AMIGADATE__" (c)1993-95 Tim Ruehsen, (c)2009-2014 Frank Wille\n\n")
#endif


#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "supp.h"


/*  Anzahl Eintraege in x_adrs  309  */
/* #define ADRCOUNT          (sizeof(x_adrs)/sizeof(struct x_adr)) */

#define ADR_OUTPUT        (1<<0)  /* Adressen im Codebereich ausgeben */
#define KEEP_BINARY       (1<<1)  /* Binaeres Zwischenfile loeschen   */
#define SHOW_RELOCINFO    (1<<2)  /* Relokations-Informationen zeigen */
#define KEEP_ZEROHUNKS    (1<<3)  /* Null-Hunks mit ausgeben          */
#define OLDSTYLE          (1<<4)  /* Use oldstyle EA-formats          */
#define SPLITFILE         (1<<5)  /* Put sections into own files      */
#define BASEREG1          (1<<6)  /* Address proposals for d16(Ax)    */
#define BASEREG2          (1<<7)  /* Base-relative mode d16(Ax)       */
#define PREPROC           (1<<8)  /* To find data in code sections    */
#define CONFIG            (1<<9)  /* Configfile should be included    */
#define FORCECODE         (1<<10) /* Mark areas ending with RTS as code */
#define ROMTAGatZERO      (1<<11) /* Don't assume a code entry at adr=0 */
#define ESCCODES          (1<<12) /* Use Escape code '\' in strings   */

#define M68000            1
#define M68010            2
#define M68020            4
#define M68030            8
#define M68040            16
#define M68060            32
#define M68851           128
#define M68881           256
#define M680x0            (1+2+4+8+16+32)
#define M010UP            (2+4+8+16+32)
#define M020UP            (4+8+16+32)
#define M030UP            (8+16+32)
#define M040UP            (16+32)


#define OPC_BITFIELD       0
#define OPC_BITSHIFT1      1
#define OPC_BITSHIFT2      2
#define OPC_RTE            6
#define OPC_RTR            7
#define OPC_RTS            8
#define OPC_RTD            9
#define OPC_DIVL          24
#define OPC_MULL          25
#define OPC_JMP           27
#define OPC_JSR           28
#define OPC_PEA           29
#define OPC_MOVEM1        35
#define OPC_MOVEM3        37
#define OPC_LEA           39
#define OPC_TST           43
#define OPC_PACK1         67
#define OPC_PACK2         68
#define OPC_UNPK1         69
#define OPC_UNPK2         70
#define OPC_MOVEB         77
#define OPC_MOVEW         79
#define OPC_MOVEAL        80
#define OPC_MOVEL         81
#define OPC_RTM           96
#define OPC_CALLM         97
#define OPC_C2            98
#define OPC_CMPI          99
#define OPC_BITOP        105
#define OPC_MOVES        106
#define OPC_DBCC         107
#define OPC_BCC          114
#define OPC_MOVE162      116


#define NOADRMODE         99     /* Addressmode for DC.W */

struct x_adr {
	const char name[12];
	unsigned long adr;
};

#define STDNAMELENGTH   256

typedef struct jmptab_s {
	int size;
	ULONG start,end,base;
} jmptab_t;

#endif /* IRA_H */
