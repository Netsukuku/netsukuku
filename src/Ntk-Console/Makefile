CXX=clang
DEBUG=-g -pthread -Wfatal-errors -pedantic -Weffc++ -Wunreachable-code -Winline -Wredundant-decls -Wno-vla
SRCBIN=Netsukuku-Console

all: ${SRCBIN}

${SRCBIN}: Netsukuku-Console.o
	${CXX} ${LDFLAGS} ${LIBS} $^ -pthread -g -o $@

.PHONY: clean

clean:
	rm -f *.o ${SRCBIN}
