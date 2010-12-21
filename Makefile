CC=gcc
CFLAGS=-std=gnu99 -fopenmp
LIBS=-framework OpenCL
EXECUTABLE=sha256crack
OUTPUT_DIR=build
INSTALL_PREFIX=/usr/local

SOURCES=sha256.c
HEADERS=$(SOURCES:.c=.h)
OBJECTS=$(addprefix $(OUTPUT_DIR)/,$(SOURCES:.c=.o))
OTHER_OBJECTS=$(addprefix $(OUTPUT_DIR)/,main.o)

all: $(OUTPUT_DIR)/$(EXECUTABLE)

$(OUTPUT_DIR)/$(EXECUTABLE): $(OBJECTS) $(OTHER_OBJECTS)
	$(CC) $(CFLAGS) $(LIBS) -o $(OUTPUT_DIR)/$(EXECUTABLE) $(OBJECTS) $(OTHER_OBJECTS)

$(OUTPUT_DIR)/main.o: main.c sha256.cl.h sha256.h
	$(CC) $(CFLAGS) -o $@ -c $<

$(OUTPUT_DIR)/%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ -c $<

sha256.cl.h: sha256.cl
	echo "const char * program_source =" > sha256.cl.h
	sed 's/"/\\\\"/g' sha256.cl | while read line; do \
		echo '"'"$$line\\\n"'"' >> sha256.cl.h; \
	done
	echo ';' >> sha256.cl.h;

install: all
	cp -f $(OUTPUT_DIR)/$(EXECUTABLE) $(INSTALL_PREFIX)/bin/$(EXECUTABLE)
	cp -f sha256crack.1 $(INSTALL_PREFIX)/share/man/man1/sha256crack.1

uninstall:
	rm -f $(INSTALL_PREFIX)/bin/$(EXECUTABLE)
	rm -f $(INSTALL_PREFIX)/share/man/man1/sha256crack.1

clean:
	rm -f $(OBJECTS) $(OTHER_OBJECTS)
	rm -f sha256.cl.h
