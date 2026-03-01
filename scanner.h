#ifndef SCANNER_H
#define SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

/* ─── Colours ─────────────────────────────────────────────────── */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define CYAN    "\033[1;36m"
#define MAGENTA "\033[1;35m"
#define WHITE   "\033[1;37m"
#define RESET   "\033[0m"

/* ─── Constants ───────────────────────────────────────────────── */
#define MAX_PORTS       65535
#define MAX_HOSTS       256
#define BANNER_LEN      256
#define TIMEOUT_SEC     1
#define MAX_THREADS     100
#define VERSION         "1.0.0"
#define AUTHOR          "BCA Cyber Security Project"

/* ─── Port status ─────────────────────────────────────────────── */
#define PORT_OPEN       1
#define PORT_CLOSED     0
#define PORT_FILTERED  -1

/* ─── Scan types ──────────────────────────────────────────────── */
typedef enum {
    SCAN_TCP_CONNECT = 1,
    SCAN_UDP,
    SCAN_PING_SWEEP,
    SCAN_OS_DETECT,
    SCAN_BANNER_GRAB,
    SCAN_FULL          /* all of the above */
} ScanType;

/* ─── Structures ──────────────────────────────────────────────── */
typedef struct {
    int    port;
    int    status;          /* PORT_OPEN / PORT_CLOSED / PORT_FILTERED */
    char   service[64];
    char   banner[BANNER_LEN];
    char   protocol[8];     /* "TCP" | "UDP" */
} PortResult;

typedef struct {
    char       ip[64];
    char       hostname[256];
    int        alive;
    int        open_count;
    PortResult ports[MAX_PORTS];
    int        port_count;
    char       os_guess[128];
    double     latency_ms;
} HostResult;

typedef struct {
    char      target_ip[64];
    char      target_range[64];   /* CIDR, e.g. 192.168.1.0/24 */
    int       start_port;
    int       end_port;
    ScanType  scan_type;
    int       verbose;
    int       timeout;
    int       threads;
    char      output_file[256];
    int       save_report;
} ScanConfig;

typedef struct {
    ScanConfig  *config;
    HostResult  *result;
    int          port_start;
    int          port_end;
} ThreadArg;

/* ─── Function prototypes ─────────────────────────────────────── */
void  print_banner(void);
void  print_help(void);
void  print_report(HostResult *hosts, int host_count, ScanConfig *cfg);
void  save_report_to_file(HostResult *hosts, int host_count, ScanConfig *cfg);

int   ping_host(const char *ip, double *latency_ms);
int   tcp_connect_scan(const char *ip, int port, char *banner, int timeout);
int   udp_scan(const char *ip, int port, int timeout);

void  scan_ports_threaded(HostResult *host, ScanConfig *cfg);
void  scan_network_range(ScanConfig *cfg, HostResult *hosts, int *host_count);
void  detect_os(HostResult *host);
const char *get_service_name(int port, const char *proto);

void  generate_cidr_ips(const char *cidr, char ips[][64], int *count);
int   resolve_hostname(const char *host, char *ip_out);
char *get_timestamp(void);

unsigned short checksum(void *b, int len);

#endif /* SCANNER_H */
