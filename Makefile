OS	=
EXT	=
CC	= gcc
CCOUT	= -o 
COPTS	= -c -O2 -Wall -Wno-pointer-sign -Wno-unused-result
LD	= $(CC)
LDOUT	= $(CCOUT)
LDFLAGS	=
include make.rules
