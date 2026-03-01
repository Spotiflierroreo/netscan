#include "scanner.h"

/* ──────────────────────────────────────────────────────────────────
   ICMP checksum
   ────────────────────────────────────────────────────────────────── */
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int    sum = 0;
    unsigned short  result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/* ──────────────────────────────────────────────────────────────────
   PING HOST  (ICMP Echo – requires root; falls back to TCP/80)
   ────────────────────────────────────────────────────────────────── */
int ping_host(const char *ip, double *latency_ms) {
    /* ---- try a quick TCP-connect to port 80 or 443 first (no root) ---- */
    struct timeval tv_start, tv_end;
    struct sockaddr_in addr;
    int sock;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);

    int test_ports[] = {80, 443, 22, 445, 8080, 23, 21, 3389, 0};

    for (int pi = 0; test_ports[pi] != 0; pi++) {
        addr.sin_port = htons(test_ports[pi]);
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        /* Non-blocking */
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        gettimeofday(&tv_start, NULL);
        connect(sock, (struct sockaddr *)&addr, sizeof(addr));

        fd_set fdset;
        struct timeval tv = {1, 0};
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) {
                gettimeofday(&tv_end, NULL);
                *latency_ms = (tv_end.tv_sec  - tv_start.tv_sec)  * 1000.0 +
                              (tv_end.tv_usec - tv_start.tv_usec) / 1000.0;
                close(sock);
                return 1; /* alive */
            }
        }
        close(sock);
    }

    /* ---- ICMP raw socket (needs root / CAP_NET_RAW) ---- */
    struct icmphdr icmp_hdr;
    char packet[64];
    struct sockaddr_in dest;
    char recv_buf[1024];

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return 0;   /* no permission – just report offline */

    struct timeval timeout = {TIMEOUT_SEC, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type             = ICMP_ECHO;
    icmp_hdr.code             = 0;
    icmp_hdr.un.echo.id       = getpid();
    icmp_hdr.un.echo.sequence = 1;
    icmp_hdr.checksum         = 0;

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));
    icmp_hdr.checksum = checksum(packet, sizeof(struct icmphdr));
    memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip);

    gettimeofday(&tv_start, NULL);
    if (sendto(sock, packet, sizeof(struct icmphdr), 0,
               (struct sockaddr *)&dest, sizeof(dest)) <= 0) {
        close(sock);
        return 0;
    }

    socklen_t addr_len = sizeof(dest);
    if (recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                 (struct sockaddr *)&dest, &addr_len) > 0) {
        gettimeofday(&tv_end, NULL);
        *latency_ms = (tv_end.tv_sec  - tv_start.tv_sec)  * 1000.0 +
                      (tv_end.tv_usec - tv_start.tv_usec) / 1000.0;
        close(sock);
        return 1;
    }
    close(sock);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────
   TCP CONNECT SCAN  (full 3-way handshake)
   Returns PORT_OPEN / PORT_CLOSED / PORT_FILTERED
   Also grabs banner if port is open.
   ────────────────────────────────────────────────────────────────── */
int tcp_connect_scan(const char *ip, int port, char *banner, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return PORT_CLOSED;

    /* Set non-blocking */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    fd_set wset, eset;
    struct timeval tv = {timeout_sec, 0};
    FD_ZERO(&wset); FD_ZERO(&eset);
    FD_SET(sock, &wset);
    FD_SET(sock, &eset);

    int sel = select(sock + 1, NULL, &wset, &eset, &tv);

    if (sel <= 0) {
        close(sock);
        return (sel == 0) ? PORT_FILTERED : PORT_CLOSED;
    }

    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error != 0) {
        close(sock);
        return PORT_CLOSED;
    }

    /* ── Banner grabbing ── */
    if (banner) {
        memset(banner, 0, BANNER_LEN);
        /* Send HTTP GET for web ports; blank probe for others */
        if (port == 80 || port == 8080 || port == 8000 || port == 8888) {
            const char *http_probe =
                "GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n";
            send(sock, http_probe, strlen(http_probe), 0);
        }

        struct timeval rtv = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
        int n = recv(sock, banner, BANNER_LEN - 1, 0);
        if (n > 0) {
            /* Sanitise – remove newlines for display */
            for (int i = 0; i < n; i++)
                if (banner[i] == '\r' || banner[i] == '\n')
                    banner[i] = ' ';
            banner[n < BANNER_LEN - 1 ? n : BANNER_LEN - 2] = '\0';
        }
    }

    close(sock);
    return PORT_OPEN;
}

/* ──────────────────────────────────────────────────────────────────
   UDP SCAN  (sends empty datagram; ICMP port-unreachable → closed)
   ────────────────────────────────────────────────────────────────── */
int udp_scan(const char *ip, int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return PORT_CLOSED;

    struct timeval tv = {timeout_sec, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    const char *probe = "\x00";
    sendto(sock, probe, 1, 0, (struct sockaddr *)&addr, sizeof(addr));

    char buf[64];
    socklen_t len = sizeof(addr);
    int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &len);
    close(sock);

    /* If we got data back → open; timeout → open|filtered */
    return (n > 0) ? PORT_OPEN : PORT_FILTERED;
}

/* ──────────────────────────────────────────────────────────────────
   HOSTNAME RESOLVER
   ────────────────────────────────────────────────────────────────── */
int resolve_hostname(const char *host, char *ip_out) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_out, 64);
    freeaddrinfo(res);
    return 1;
}

/* ──────────────────────────────────────────────────────────────────
   REVERSE DNS
   ────────────────────────────────────────────────────────────────── */
static void reverse_dns(const char *ip, char *hostname_out, size_t maxlen) {
    struct sockaddr_in sa;
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);
    getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                hostname_out, maxlen, NULL, 0, NI_NAMEREQD);
}

/* ──────────────────────────────────────────────────────────────────
   OS FINGERPRINTING  (TTL heuristic via TCP options)
   ────────────────────────────────────────────────────────────────── */
void detect_os(HostResult *host) {
    /* Simple open-port heuristic */
    int has_rdp = 0, has_smb = 0, has_ssh = 0,
        has_http = 0, has_mysql = 0, has_snmp = 0;

    for (int i = 0; i < host->port_count; i++) {
        if (host->ports[i].status != PORT_OPEN) continue;
        int p = host->ports[i].port;
        if (p == 3389) has_rdp  = 1;
        if (p == 445)  has_smb  = 1;
        if (p == 22)   has_ssh  = 1;
        if (p == 80 || p == 443) has_http  = 1;
        if (p == 3306) has_mysql = 1;
        if (p == 161)  has_snmp  = 1;
    }

    if (has_rdp && has_smb)
        strncpy(host->os_guess, "Windows (RDP + SMB detected)", 127);
    else if (has_smb && !has_ssh)
        strncpy(host->os_guess, "Likely Windows (SMB, no SSH)", 127);
    else if (has_ssh && has_mysql)
        strncpy(host->os_guess, "Likely Linux/Unix (SSH + MySQL)", 127);
    else if (has_ssh && has_http)
        strncpy(host->os_guess, "Likely Linux/Unix Web Server", 127);
    else if (has_ssh)
        strncpy(host->os_guess, "Likely Linux/Unix (SSH only)", 127);
    else if (has_snmp)
        strncpy(host->os_guess, "Network Device (SNMP enabled)", 127);
    else
        strncpy(host->os_guess, "Unknown / Insufficient data", 127);
}

/* ──────────────────────────────────────────────────────────────────
   THREAD WORKER  (scans a port range for one host)
   ────────────────────────────────────────────────────────────────── */
static void *port_scan_worker(void *arg) {
    ThreadArg *ta   = (ThreadArg *)arg;
    ScanConfig *cfg = ta->config;
    HostResult *host = ta->result;

    for (int port = ta->port_start; port <= ta->port_end; port++) {
        char banner[BANNER_LEN];
        memset(banner, 0, BANNER_LEN);

        int status = tcp_connect_scan(host->ip, port, banner, cfg->timeout);

        if (status == PORT_OPEN || cfg->verbose) {
            /* Find next slot (thread-safe enough for our use case) */
            static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
            pthread_mutex_lock(&lock);
            int idx = host->port_count++;
            pthread_mutex_unlock(&lock);

            host->ports[idx].port   = port;
            host->ports[idx].status = status;
            strncpy(host->ports[idx].protocol, "TCP", 7);
            strncpy(host->ports[idx].service,
                    get_service_name(port, "TCP"), 63);
            if (strlen(banner) > 0)
                strncpy(host->ports[idx].banner, banner, BANNER_LEN - 1);

            if (status == PORT_OPEN)
                host->open_count++;
        }
    }
    free(ta);
    return NULL;
}

/* ──────────────────────────────────────────────────────────────────
   THREADED PORT SCAN  – splits port range across N threads
   ────────────────────────────────────────────────────────────────── */
void scan_ports_threaded(HostResult *host, ScanConfig *cfg) {
    int total  = cfg->end_port - cfg->start_port + 1;
    int n_thr  = cfg->threads < total ? cfg->threads : total;
    int chunk  = total / n_thr;

    pthread_t *tids = calloc(n_thr, sizeof(pthread_t));

    for (int i = 0; i < n_thr; i++) {
        ThreadArg *ta = malloc(sizeof(ThreadArg));
        ta->config      = cfg;
        ta->result      = host;
        ta->port_start  = cfg->start_port + i * chunk;
        ta->port_end    = (i == n_thr - 1)
                          ? cfg->end_port
                          : ta->port_start + chunk - 1;
        pthread_create(&tids[i], NULL, port_scan_worker, ta);
    }
    for (int i = 0; i < n_thr; i++)
        pthread_join(tids[i], NULL);

    free(tids);

    /* Reverse DNS */
    memset(host->hostname, 0, sizeof(host->hostname));
    reverse_dns(host->ip, host->hostname, sizeof(host->hostname));
    if (strlen(host->hostname) == 0)
        strncpy(host->hostname, "N/A", 255);
}

/* ──────────────────────────────────────────────────────────────────
   CIDR EXPANSION  e.g. 192.168.1.0/24  →  192.168.1.1 … .254
   ────────────────────────────────────────────────────────────────── */
void generate_cidr_ips(const char *cidr, char ips[][64], int *count) {
    char network[64];
    int  prefix;
    *count = 0;

    sscanf(cidr, "%63[^/]/%d", network, &prefix);
    uint32_t base = ntohl(inet_addr(network));
    uint32_t mask = prefix == 0 ? 0 : (~0u << (32 - prefix));
    uint32_t start = (base & mask) + 1;
    uint32_t end   = (base | ~mask) - 1;

    if (end - start > MAX_HOSTS - 1)
        end = start + MAX_HOSTS - 1;

    for (uint32_t ip = start; ip <= end; ip++, (*count)++) {
        struct in_addr a = { .s_addr = htonl(ip) };
        inet_ntop(AF_INET, &a, ips[*count], 64);
    }
}

/* ──────────────────────────────────────────────────────────────────
   SCAN NETWORK RANGE  (ping sweep + port scan per alive host)
   ────────────────────────────────────────────────────────────────── */
void scan_network_range(ScanConfig *cfg, HostResult *hosts, int *host_count) {
    char ips[MAX_HOSTS][64];
    int  ip_count = 0;

    if (strchr(cfg->target_range, '/')) {
        generate_cidr_ips(cfg->target_range, ips, &ip_count);
    } else {
        strncpy(ips[0], cfg->target_ip, 63);
        ip_count = 1;
    }

    printf(CYAN "\n[*] Discovering live hosts in %s ...\n" RESET,
           ip_count > 1 ? cfg->target_range : cfg->target_ip);

    *host_count = 0;
    for (int i = 0; i < ip_count; i++) {
        double latency = 0;
        int alive = ping_host(ips[i], &latency);
        if (alive) {
            printf(GREEN "  [+] Host UP: %-18s  latency: %.2f ms\n" RESET,
                   ips[i], latency);
            strncpy(hosts[*host_count].ip, ips[i], 63);
            hosts[*host_count].alive      = 1;
            hosts[*host_count].latency_ms = latency;
            hosts[*host_count].open_count = 0;
            hosts[*host_count].port_count = 0;
            (*host_count)++;
        } else if (cfg->verbose) {
            printf(RED "  [-] Host DOWN: %s\n" RESET, ips[i]);
        }
    }
}

/* ──────────────────────────────────────────────────────────────────
   TIMESTAMP
   ────────────────────────────────────────────────────────────────── */
char *get_timestamp(void) {
    static char buf[32];
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}
