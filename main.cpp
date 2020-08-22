#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <cerrno>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "protocol-hdr.h"

// function prototypes
int parse(unsigned char* buf, int size); 
static u_int32_t print_pkt (struct nfq_data *tb, int *decide_type);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data);

// function that shows usage
void usage() {
	printf("syntax: netfilter-test <host>\n");
	printf("sample: netfilter-test test.gilgil.net\n");
}

// global variables
char *block_host;

int main(int argc, char **argv)
{
	// check syntax
	if (argc != 2) {
		usage();
		return -1;
	}
	
	block_host = argv[1];

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	return 0;
}


int parse(unsigned char* buf, int size) {
	// adjust the packet with IPv4 protocol
	IPv4 *ipv4 = (IPv4*) buf;

	// check if IP protocol type is TCP or not
	if (ipv4->proto != IP_PROTO_TCP) {
		// printf("Info: this packet is not TCP (IPv4_Protocol == 0x%x)\n\n", ipv4->proto);
		return NF_ACCEPT;
	}

	// get IP header length
	uint8_t ip_hdrlen = ipv4->get_ip_hdrlen();

	// adjust the packet with TCP protocol
	TCP *tcp = (TCP*) (buf + ip_hdrlen);

	// get TCP header length
	uint8_t tcp_hdrlen = tcp->get_tcp_hdrlen();

	// adjust the packet to data (payload)
	const uint8_t *data = buf + ip_hdrlen + tcp_hdrlen;
	
	// parsing HTTP host
	std::string key("Host: ");
	std::string payload;
	payload.assign((const char*)data);
	size_t found_host = payload.find(key);
	size_t found_endline = std::string::npos;
	std::string host;
	if (found_host != std::string::npos) {
		found_host += key.length();
		found_endline = payload.find("\r\n", found_host+1);
	}
	if (found_endline != std::string::npos) {
		host = payload.substr(found_host, found_endline-found_host);
		// printf("\n\n%s\n\n", host.c_str());
		
		if (host == block_host) {
			printf("** Blocked the host! **\n");
			return NF_DROP;
		}
	}
	
	/*
	printf("\n");
	for (int i = 0; (data + i) < (buf + size); i++) {
		// ipv4->tot_len == ip_hdrlen + tcp_hdrlen + payload
		printf("%c", data[i]);
	}
	printf("\n\n");
	*/
	
	return NF_ACCEPT;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, int *decide_type)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		if (decide_type != NULL) {
			*decide_type = parse(data, ret);
		}
		printf("payload_len=%d ", ret);
	}

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int type;
	u_int32_t id = print_pkt(nfa, &type);
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, type, 0, NULL);
}
