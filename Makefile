OBJECTS = readex.o dextypes.o utils.o
CC = gcc
FLAG = -c -g

readex: $(OBJECTS)
	$(CC) -o readex $(OBJECTS)

readex.o: readex.c
	$(CC) $(FLAG) readex.c

dextypes.o: dextypes.c
	$(CC) $(FLAG) dextypes.c

utils.o: utils.c
	$(CC) $(FLAG) utils.c

.PHONY: clean
clean:
	rm -f $(OBJECTS) readex

.PHONY: test
test: readex
	./readex Hello.dex