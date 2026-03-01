#include "scanner.h"

/* ══════════════════════════════════════════════════════════════════
   MAIN
   ══════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[]) {

    print_banner();

    /* ── Default config ── */
    ScanConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.start_port  = 1;
    cfg.end_port    = 1024;
    cfg.scan_type   = SCAN_FULL;
    cfg.timeout     = TIMEOUT_SEC;
    cfg.threads     = 50;
    cfg.verbose     = 0;
    cfg.save_report = 0;

    /* ── Parse arguments ── */
    if (argc == 1) {
        print_help();
        printf(YELLOW "[!] No arguments supplied. Running interactive mode.\n\n" RESET);

        /* Interactive prompts */
        printf(WHITE "Enter target IP or CIDR range: " RESET);
        scanf("%63s", cfg.target_ip);
        strncpy(cfg.target_range, cfg.target_ip, 63);

        printf(WHITE "Port range [1-1024]: " RESET);
        char port_buf[32] = "";
        scanf("%31s", port_buf);
        if (strlen(port_buf) > 0 && strchr(port_buf, '-')) {
            sscanf(port_buf, "%d-%d", &cfg.start_port, &cfg.end_port);
        }

        printf(WHITE "Scan type (1=TCP 2=UDP 3=Ping 4=OS 5=Banner 6=Full) [6]: " RESET);
        int st = 6;
        scanf("%d", &st);
        cfg.scan_type = st;

        printf(WHITE "Threads [50]: " RESET);
        int th = 50;
        scanf("%d", &th);
        cfg.threads = th;

        printf(WHITE "Save report? (0=No, 1=Yes) [0]: " RESET);
        int sv = 0;
        scanf("%d", &sv);
        if (sv) {
            cfg.save_report = 1;
            printf(WHITE "Output filename [report.txt]: " RESET);
            scanf("%255s", cfg.output_file);
            if (strlen(cfg.output_file) == 0)
                strncpy(cfg.output_file, "report.txt", 255);
        }
    } else {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
                strncpy(cfg.target_ip,    argv[++i], 63);
                strncpy(cfg.target_range, cfg.target_ip, 63);
            } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
                sscanf(argv[++i], "%d-%d", &cfg.start_port, &cfg.end_port);
            } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
                cfg.scan_type = atoi(argv[++i]);
            } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
                cfg.threads = atoi(argv[++i]);
            } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                strncpy(cfg.output_file, argv[++i], 255);
                cfg.save_report = 1;
            } else if (strcmp(argv[i], "-v") == 0) {
                cfg.verbose = 1;
            } else if (strcmp(argv[i], "-h") == 0) {
                print_help();
                return 0;
            } else {
                printf(RED "[!] Unknown option: %s\n" RESET, argv[i]);
                print_help();
                return 1;
            }
        }
    }

    /* ── Validate ── */
    if (strlen(cfg.target_ip) == 0) {
        fprintf(stderr, RED "[!] No target specified. Use -t <ip/range>\n" RESET);
        return 1;
    }
    if (cfg.start_port < 1 || cfg.end_port > 65535 ||
        cfg.start_port > cfg.end_port) {
        fprintf(stderr, RED "[!] Invalid port range.\n" RESET);
        return 1;
    }
    if (cfg.threads < 1 || cfg.threads > MAX_THREADS)
        cfg.threads = 50;

    /* Resolve hostname → IP if needed */
    if (!inet_addr(cfg.target_ip)) {
        char resolved[64] = "";
        if (resolve_hostname(cfg.target_ip, resolved)) {
            printf(CYAN "[*] Resolved %s → %s\n" RESET, cfg.target_ip, resolved);
            strncpy(cfg.target_ip,    resolved, 63);
            strncpy(cfg.target_range, resolved, 63);
        }
    }

    /* ── Print scan config ── */
    printf(CYAN "\n[*] Scan Configuration\n" RESET);
    printf("    Target     : %s\n", cfg.target_range);
    printf("    Ports      : %d - %d  (%d ports)\n",
           cfg.start_port, cfg.end_port,
           cfg.end_port - cfg.start_port + 1);
    printf("    Scan Type  : ");
    switch (cfg.scan_type) {
        case SCAN_TCP_CONNECT: printf("TCP Connect\n");   break;
        case SCAN_UDP:         printf("UDP\n");           break;
        case SCAN_PING_SWEEP:  printf("Ping Sweep\n");    break;
        case SCAN_OS_DETECT:   printf("OS Detection\n");  break;
        case SCAN_BANNER_GRAB: printf("Banner Grab\n");   break;
        default:               printf("Full Scan\n");     break;
    }
    printf("    Threads    : %d\n", cfg.threads);
    printf("    Verbose    : %s\n\n", cfg.verbose ? "Yes" : "No");

    /* ── Allocate results ── */
    HostResult *hosts = calloc(MAX_HOSTS, sizeof(HostResult));
    int         host_count = 0;
    time_t      t_start = time(NULL);

    /* ══ PING SWEEP ══ */
    if (cfg.scan_type == SCAN_PING_SWEEP) {
        scan_network_range(&cfg, hosts, &host_count);
        goto done;
    }

    /* ══ HOST DISCOVERY ══ */
    if (strchr(cfg.target_range, '/')) {
        scan_network_range(&cfg, hosts, &host_count);
    } else {
        /* Single target */
        double lat = 0;
        printf(CYAN "[*] Checking if host is alive ...\n" RESET);
        int alive = ping_host(cfg.target_ip, &lat);
        if (!alive) {
            printf(YELLOW "[!] Host appears down. Scanning anyway...\n" RESET);
        } else {
            printf(GREEN "[+] Host is UP  (latency: %.2f ms)\n" RESET, lat);
        }
        strncpy(hosts[0].ip, cfg.target_ip, 63);
        hosts[0].alive      = alive;
        hosts[0].latency_ms = lat;
        host_count = 1;
    }

    if (host_count == 0) {
        printf(RED "\n[!] No live hosts found.\n" RESET);
        free(hosts);
        return 0;
    }

    /* ══ PORT SCANNING ══ */
    if (cfg.scan_type != SCAN_OS_DETECT) {
        for (int h = 0; h < host_count; h++) {
            printf(CYAN "\n[*] Scanning %s  (ports %d–%d)  ...\n" RESET,
                   hosts[h].ip, cfg.start_port, cfg.end_port);

            scan_ports_threaded(&hosts[h], &cfg);

            printf(GREEN "[+] Finished %s : %d open ports found\n" RESET,
                   hosts[h].ip, hosts[h].open_count);
        }
    }

    /* ══ OS DETECTION ══ */
    if (cfg.scan_type == SCAN_OS_DETECT || cfg.scan_type == SCAN_FULL) {
        printf(CYAN "\n[*] Running OS detection ...\n" RESET);
        for (int h = 0; h < host_count; h++)
            detect_os(&hosts[h]);
    }

done:
    /* ── Print report ── */
    time_t elapsed = time(NULL) - t_start;
    print_report(hosts, host_count, &cfg);
    printf(WHITE "[*] Scan duration: %ld second(s)\n" RESET, elapsed);

    if (cfg.save_report)
        save_report_to_file(hosts, host_count, &cfg);

    free(hosts);
    return 0;
}
