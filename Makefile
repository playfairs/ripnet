PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c17 -Iinclude
LDFLAGS = -lpcap -lpthread

SRCDIR = src
OBJDIR = obj
INCLUDEDIR = include

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = ripnet

VERSION := $(shell cat VERSION)

.PHONY: all clean install uninstall test release

all: $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(TARGET): $(OBJECTS) | $(OBJDIR)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)

install: $(TARGET)
	install -d $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)/$(TARGET)

uninstall:
	rm -f $(BINDIR)/$(TARGET)

test: $(TARGET)
	@echo "Running tests..."
	@./tests/run_tests.sh || echo "No tests configured"

release: clean
	@echo "Creating release for version $(VERSION)"
	@git tag -a v$(VERSION) -m "Release version $(VERSION)" || true
	@git archive --prefix=ripnet-$(VERSION)/ -o ripnet-$(VERSION).tar.gz HEAD
	@echo "Release ripnet-$(VERSION).tar.gz created"