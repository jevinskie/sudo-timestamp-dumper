TARGETS := sudo-timestamp-dumper
TARGETS_SUID := sudo-timestamp-dumper-suid

C_FLAGS := -Wall -Wextra -Wpedantic -std=c11

ifneq ($(shell uname -s),Darwin)
C_FLAGS += $(C_FLAGS) -lcap-ng
PRIVESC_GROUP = admin
PRIVESC_SETCAP = sudo setcap cap_setuid,cap_setgid+eip $@
else
PRIVESC_GROUP = wheel
PRIVESC_SETCAP =
endif

all: $(TARGETS)
all-suid: $(TARGETS_SUID)

.PHONY: clean clean-suid

clean:
	rm -rf *.dSYM/
	rm -f $(TARGETS)

clean-suid: clean
	sudo rm -rf *.dSYM/
	sudo rm -rf $(TARGETS_SUID)

sudo-timestamp-dumper: sudo-timestamp-dumper.c
	$(CC) -o $@ $^ $(C_FLAGS)

sudo-timestamp-dumper-suid: sudo-timestamp-dumper
	sudo cp $^ $@
	sudo chown root:$(PRIVESC_GROUP) $@
	sudo chmod u+s $@
	sudo chmod g+s $@
	$(PRIVESC_SETCAP)
