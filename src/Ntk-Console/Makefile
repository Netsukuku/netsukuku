C=clang
DEBUG=-g -fno-builtin -Wfatal-errors -pedantic -Wunreachable-code -Winline -Wredundant-decls -Wno-vla
CFLAGS=-Wall ${DEBUG}
SRCBIN=Netsukuku-Console

all: ${SRCBIN}

${SRCBIN}: Netsukuku-Console.o
	${C} ${LDFLAGS} ${LIBS} $^ -o $@

.PHONY: clean

clean:
	rm -f *.o ${SRCBIN}
