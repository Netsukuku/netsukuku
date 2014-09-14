C=clang
DEBUG=-g -fno-builtin -Wfatal-errors -pedantic -Wunreachable-code -Winline -Wredundant-decls -Wno-vla
CFLAGS=-Wall ${DEBUG} -std=c99
SRCBIN=Netsukuku-Console

all: ${SRCBIN}

${SRCBIN}: Netsukuku-Console.o
	${C} ${LDFLAGS} ${CFLAGS} ${LIBS} $^ -o $@

.PHONY: clean

clean:
	rm -f *.o ${SRCBIN}
