#define PCAP_NETMASK_UNKNOWN ...
#define PCAP_ERRBUF_SIZE ...
#define PCAP_TSTAMP_PRECISION_MICRO ...

#define DLT_EN10MB ...
#define DLT_LINUX_SLL ...

#define ETH_P_IP ...
#define ETH_P_ARP ...
#define ETH_P_IPV6 ...

typedef int... time_t;
typedef int... suseconds_t;
typedef int... u_char;
typedef int... u_int;
typedef int... bpf_u_int32;

struct timeval {
    time_t tv_sec;
    suseconds_t tv_usec;
};

typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);

struct pcap_pkthdr {
    struct timeval ts;
    bpf_u_int32 len;
    ...;
};

struct pcap_stat {
    u_int ps_recv;
    u_int ps_drop;
    u_int ps_ifdrop;
};

struct bpf_insn;
struct bpf_program {
    u_int bf_len;
    struct bpf_insn *bf_insns;
};

char *pcap_lookupdev(char *);
pcap_t *pcap_create(const char *, char *);
pcap_t *pcap_open_offline_with_tstamp_precision(const char *, u_int, char *);
void pcap_close(pcap_t *);
int pcap_activate(pcap_t *);
int pcap_set_snaplen(pcap_t *, int);
int pcap_set_promisc(pcap_t *, int);
int pcap_set_timeout(pcap_t *, int);
int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
int pcap_stats(pcap_t *, struct pcap_stat *);
int pcap_setnonblock(pcap_t *, int, char *);
int pcap_getnonblock(pcap_t *, char *);
int pcap_datalink(pcap_t *);
const char *pcap_lib_version(void);
char *pcap_geterr(pcap_t *);
pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
void pcap_dump_close(pcap_dumper_t *);
void pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *);
int pcap_get_selectable_fd(pcap_t *);
int pcap_setfilter(pcap_t *, struct bpf_program *);
int pcap_compile(pcap_t *, struct bpf_program *, const char *, int, unsigned int);
int pcap_dispatch(pcap_t *, int cnt, pcap_handler callback, u_char *);

extern "Python" void dumper_dispatch(u_char *, const struct pcap_pkthdr *, const u_char *);
