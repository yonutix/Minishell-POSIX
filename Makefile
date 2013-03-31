CC=gcc
CFLAGS=-g -Wall
OBJ_PARSER=parser.tab.o parser.yy.o
OBJ=main.o utils-lin.o
TARGET=mini-shell

build: $(TARGET)

$(TARGET): $(OBJ) $(OBJ_PARSER)
	$(CC) $(CFLAGS) $(OBJ) $(OBJ_PARSER) -o $(TARGET)

parser.tab.o: parser.tab.c
	gcc -c -o parser.tab.o parser.tab.c

parser.yy.o: parser.yy.c
	gcc -c -o parser.yy.o parser.yy.c

utils-lin.o: utils-lin.c
	gcc -c -o utils-lin.o utils-lin.c

main.o: main.c
	gcc -c -o main.o main.c

clean:
	rm -rf $(OBJ) $(OBJ_PARSER) $(TARGET) *~
