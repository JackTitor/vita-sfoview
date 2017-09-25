
SRC		= main.c
CC		= gcc

OPTS	= -O3 -Wall -Werror -Wfloat-equal
DOPTS	= $(OPTS) -O0 -g -D DEBUG -D _GLIBCXX_DEBUG

ARGS	= ./param.sfo

OUT		= ./a.out
DOUT	= ./debug.out

.PHONY: run debug gdb time clean test drun

$(OUT): $(SRC)
	$(CC) $(OPTS) -o $(OUT) $(SRC)

$(DOUT): $(SRC)
	$(CC) $(DOPTS) -o $(DOUT) $(SRC)

bin: $(OUT)
	
debug: $(DOUT)
	
run: $(OUT)
	$(OUT) $(ARGS)

drun: $(DOUT)
	$(DOUT) $(ARGS)

gdb: $(DOUT)
	gdb --quiet --args $(DOUT) $(ARGS)

time: $(OUT)
	time -p $(OUT) $(ARGS) > /dev/null

clean:
	rm -f main.o
