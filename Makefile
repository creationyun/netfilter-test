LDLIBS=-lnetfilter_queue

all: netfilter-test

netfilter-test: net-address.o protocol-hdr.o main.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f netfilter-test *.o
