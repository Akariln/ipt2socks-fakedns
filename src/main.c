#define _GNU_SOURCE
#include "ctx.h"
#include "fakedns.h"
#include "logutils.h"
#include "lrucache.h"
#include "mempool.h"
#include "netutils.h"
#include "socks5.h"
#include "tcp_proxy.h"
#include "udp_proxy.h"

#include "../libev/ev.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define IPT2SOCKS_VERSION "ipt2socks original <https://github.com/zfl9/ipt2socks>\nipt2socks-fakedns v1.1.6 <https://github.com/wyzhou-com/ipt2socks-fakedns>"

static void* run_event_loop(void *is_main_thread);

static void print_command_help(void) {
    printf("usage: ipt2socks <options...>. the existing options are as follows:\n"
           " -s, --server-addr <addr>           socks5 server ip, default: 127.0.0.1\n"
           " -p, --server-port <port>           socks5 server port, default: 1080\n"
           " -a, --auth-username <user>         username for socks5 authentication\n"
           " -k, --auth-password <passwd>       password for socks5 authentication\n"
           " -b, --listen-addr4 <addr>          listen ipv4 address, default: 127.0.0.1\n"
           " -B, --listen-addr6 <addr>          listen ipv6 address, default: ::1\n"
           " -l, --listen-port <port>           listen port number, default: 60080\n"
           " -S, --tcp-syncnt <cnt>             change the number of tcp syn retransmits\n"
           " -c, --cache-size <size>            udp context cache maxsize, default: 256\n"
           " -o, --udp-timeout <sec>            udp context idle timeout, default: 60\n"
           " -j, --thread-nums <num>            number of the worker threads, default: 1\n"
           " -n, --nofile-limit <num>           set nofile limit, may need root privilege\n"
           " -u, --run-user <user>              run as the given user, need root privilege\n"
           " -T, --tcp-only                     listen tcp only, aka: disable udp proxy\n"
           " -U, --udp-only                     listen udp only, aka: disable tcp proxy\n"
           " -4, --ipv4-only                    listen ipv4 only, aka: disable ipv6 proxy\n"
           " -6, --ipv6-only                    listen ipv6 only, aka: disable ipv4 proxy\n"
           " -R, --redirect                     use redirect instead of tproxy for tcp\n"
           " -r, --reuse-port                   enable so_reuseport for single thread\n"
           " -w, --tfo-accept                   enable tcp_fastopen for server socket\n"
           " -W, --tfo-connect                  enable tcp_fastopen for client socket\n"
           " -v, --verbose                      print verbose log, affect performance\n"
           " -V, --version                      print ipt2socks version number and exit\n"
           " -h, --help                         print ipt2socks help information and exit\n"
           "     --enable-fakedns               enable fakedns feature\n"
           "     --fakedns-addr <addr>          fakedns listen address, default: 127.0.0.1\n"
           "     --fakedns-port <port>          fakedns listen port, default: 5353\n"
           "     --fakedns-ip-range <cidr>      fakedns ip range, default: 198.18.0.0/15\n"
           "     --fakedns-cache <path>         fakedns cache file path, support persistence\n"
    );
}

/**
 * Validate IP address string.
 * @param ipstr IP address string to validate
 * @param max_len Maximum allowed length (including null terminator)
 * @param required_family Required address family (AF_INET, AF_INET6, or -1 for any)
 * @param opt_name Option name for error messages
 * @return true if valid, false if invalid (error message printed)
 */
static bool validate_ip_address(const char *ipstr, size_t max_len, int required_family, const char *opt_name) {
    if (strlen(ipstr) + 1 > max_len) {
        printf("[parse_command_args] %s address max length is %zu: %s\n", opt_name, max_len - 1, ipstr);
        return false;
    }
    int family = get_ipstr_family(ipstr);
    if (required_family == -1) {
        if (family == -1) {
            printf("[parse_command_args] invalid %s ip address: %s\n", opt_name, ipstr);
            return false;
        }
    } else if (family != required_family) {
        printf("[parse_command_args] invalid %s %s address: %s\n", opt_name, 
               required_family == AF_INET ? "ipv4" : "ipv6", ipstr);
        return false;
    }
    return true;
}

/**
 * Validate and parse port number.
 * @param portstr Port number string to validate
 * @param out_port Output port number (set only if valid)
 * @param opt_name Option name for error messages
 * @return true if valid, false if invalid (error message printed)
 */
static bool validate_port_number(const char *portstr, portno_t *out_port, const char *opt_name) {
    char *endptr;
    unsigned long port = strtoul(portstr, &endptr, 10);
    if (*endptr != '\0' || port == 0 || port > 65535) {
        printf("[parse_command_args] invalid %s port number: %s\n", opt_name, portstr);
        return false;
    }
    *out_port = (portno_t)port;
    return true;
}

/**
 * Validate and parse unsigned integer within range.
 * @param valstr Value string to validate
 * @param max_val Maximum allowed value
 * @param out_val Output value (set only if valid)
 * @param opt_name Option name for error messages
 * @return true if valid, false if invalid (error message printed)
 */
static bool validate_uint_range(const char *valstr, unsigned long max_val, unsigned long *out_val, const char *opt_name) {
    char *endptr;
    unsigned long val = strtoul(valstr, &endptr, 10);
    if (*endptr != '\0' || val == 0 || val > max_val) {
        printf("[parse_command_args] invalid %s: %s\n", opt_name, valstr);
        return false;
    }
    *out_val = val;
    return true;
}

static void parse_command_args(int argc, char* argv[]) {
    opterr = 0;
    const char *optstr = ":s:p:a:k:b:B:l:S:c:o:j:n:u:TU46RrwWvVh";
    const struct option options[] = {
        {"server-addr",   required_argument, NULL, 's'},
        {"server-port",   required_argument, NULL, 'p'},
        {"auth-username", required_argument, NULL, 'a'},
        {"auth-password", required_argument, NULL, 'k'},
        {"listen-addr4",  required_argument, NULL, 'b'},
        {"listen-addr6",  required_argument, NULL, 'B'},
        {"listen-port",   required_argument, NULL, 'l'},
        {"tcp-syncnt",    required_argument, NULL, 'S'},
        {"cache-size",    required_argument, NULL, 'c'},
        {"udp-timeout",   required_argument, NULL, 'o'},
        {"thread-nums",   required_argument, NULL, 'j'},
        {"nofile-limit",  required_argument, NULL, 'n'},
        {"run-user",      required_argument, NULL, 'u'},
        {"tcp-only",      no_argument,       NULL, 'T'},
        {"udp-only",      no_argument,       NULL, 'U'},
        {"ipv4-only",     no_argument,       NULL, '4'},
        {"ipv6-only",     no_argument,       NULL, '6'},
        {"redirect",      no_argument,       NULL, 'R'},
        {"reuse-port",    no_argument,       NULL, 'r'},
        {"tfo-accept",    no_argument,       NULL, 'w'},
        {"tfo-connect",   no_argument,       NULL, 'W'},
        {"verbose",       no_argument,       NULL, 'v'},
        {"version",       no_argument,       NULL, 'V'},
        {"help",          no_argument,       NULL, 'h'},
        {"enable-fakedns",no_argument,       NULL, 1001},
        {"fakedns-addr",  required_argument, NULL, 1002},
        {"fakedns-port",  required_argument, NULL, 1003},
        {"fakedns-ip-range", required_argument, NULL, 1004},
        {"fakedns-cache", required_argument, NULL, 1005},
        {NULL,            0,                 NULL,   0},
    };

    const char *optval_auth_username = NULL;
    const char *optval_auth_password = NULL;

    int shortopt = -1;
    while ((shortopt = getopt_long(argc, argv, optstr, options, NULL)) != -1) {
        switch (shortopt) {
            case 's':
                if (!validate_ip_address(optarg, IP6STRLEN, -1, "server"))
                    goto PRINT_HELP_AND_EXIT;
                strcpy(g_server_ipstr, optarg);
                break;
            case 'p':
                if (!validate_port_number(optarg, &g_server_portno, "server"))
                    goto PRINT_HELP_AND_EXIT;
                break;
            case 'a':
                if (strlen(optarg) > SOCKS5_USRPWD_USRMAXLEN) {
                    printf("[parse_command_args] socks5 username max length is 255: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                optval_auth_username = optarg;
                break;
            case 'k':
                if (strlen(optarg) > SOCKS5_USRPWD_PWDMAXLEN) {
                    printf("[parse_command_args] socks5 password max length is 255: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                optval_auth_password = optarg;
                break;
            case 'b':
                if (!validate_ip_address(optarg, IP4STRLEN, AF_INET, "listen"))
                    goto PRINT_HELP_AND_EXIT;
                strcpy(g_bind_ipstr4, optarg);
                break;
            case 'B':
                if (!validate_ip_address(optarg, IP6STRLEN, AF_INET6, "listen"))
                    goto PRINT_HELP_AND_EXIT;
                strcpy(g_bind_ipstr6, optarg);
                break;
            case 'l':
                if (!validate_port_number(optarg, &g_bind_portno, "listen"))
                    goto PRINT_HELP_AND_EXIT;
                break;
            case 'S': {
                unsigned long val;
                if (!validate_uint_range(optarg, 255, &val, "number of syn retransmits"))
                    goto PRINT_HELP_AND_EXIT;
                g_tcp_syncnt_max = (uint8_t)val;
                break;
            }
            case 'c': {
                unsigned long val;
                if (!validate_uint_range(optarg, 65535, &val, "maxsize of udp lrucache"))
                    goto PRINT_HELP_AND_EXIT;
                lrucache_set_maxsize((uint16_t)val);
                break;
            }
            case 'o': {
                unsigned long val;
                if (!validate_uint_range(optarg, 65535, &val, "udp socket idle timeout"))
                    goto PRINT_HELP_AND_EXIT;
                g_udp_idletimeout_sec = (uint16_t)val;
                break;
            }
            case 'j': {
                unsigned long val;
                if (!validate_uint_range(optarg, 255, &val, "number of worker threads"))
                    goto PRINT_HELP_AND_EXIT;
                g_nthreads = (uint8_t)val;
                break;
            }
            case 'n': {
                unsigned long val;
                if (!validate_uint_range(optarg, ULONG_MAX, &val, "nofile limit"))
                    goto PRINT_HELP_AND_EXIT;
                set_nofile_limit(val);
                break;
            }
            case 'u':
                run_as_user(optarg, argv);
                break;
            case 'T':
                g_options &= ~OPT_ENABLE_UDP;
                break;
            case 'U':
                g_options &= ~OPT_ENABLE_TCP;
                break;
            case '4':
                g_options &= ~OPT_ENABLE_IPV6;
                break;
            case '6':
                g_options &= ~OPT_ENABLE_IPV4;
                break;
            case 'R':
                g_options |= OPT_TCP_USE_REDIRECT;
                strcpy(g_bind_ipstr4, IP4STR_WILDCARD);
                strcpy(g_bind_ipstr6, IP6STR_WILDCARD);
                break;
            case 'r':
                g_options |= OPT_ALWAYS_REUSE_PORT;
                break;
            case 'w':
                g_options |= OPT_ENABLE_TFO_ACCEPT;
                break;
            case 'W':
                g_options |= OPT_ENABLE_TFO_CONNECT;
                break;
            case 'v':
                g_verbose = true;
                break;
            case 'V':
                printf(IPT2SOCKS_VERSION"\n");
                exit(0);
            case 'h':
                print_command_help();
                exit(0);
            case ':':
                printf("[parse_command_args] missing optarg: '%s'\n", argv[optind - 1]);
                goto PRINT_HELP_AND_EXIT;
            case '?':
                if (optopt) {
                    printf("[parse_command_args] unknown option: '-%c'\n", optopt);
                } else {
                    char *longopt = argv[optind - 1];
                    char *equalsign = strchr(longopt, '=');
                    if (equalsign) *equalsign = 0;
                    printf("[parse_command_args] unknown option: '%s'\n", longopt);
                }
                goto PRINT_HELP_AND_EXIT;
            case 1001:
                g_options |= OPT_ENABLE_FAKEDNS;
                break;
            case 1002:
                if (!validate_ip_address(optarg, IP4STRLEN, AF_INET, "fakedns"))
                    goto PRINT_HELP_AND_EXIT;
                strcpy(g_fakedns_ipstr, optarg);
                break;
            case 1003:
                if (!validate_port_number(optarg, &g_fakedns_portno, "fakedns"))
                    goto PRINT_HELP_AND_EXIT;
                break;
            case 1004:
                strncpy(g_fakedns_cidr, optarg, sizeof(g_fakedns_cidr) - 1);
                g_fakedns_cidr[sizeof(g_fakedns_cidr) - 1] = '\0';
                break;
            case 1005:
                strncpy(g_fakedns_cache_path, optarg, sizeof(g_fakedns_cache_path) - 1);
                g_fakedns_cache_path[sizeof(g_fakedns_cache_path) - 1] = '\0';
                break;
        }
    }

    if (!(g_options & (OPT_ENABLE_TCP | OPT_ENABLE_UDP))) {
        printf("[parse_command_args] both tcp and udp are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!(g_options & (OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6))) {
        printf("[parse_command_args] both ipv4 and ipv6 are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }

    if (optval_auth_username && !optval_auth_password) {
        printf("[parse_command_args] username specified, but password is not provided\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!optval_auth_username && optval_auth_password) {
        printf("[parse_command_args] password specified, but username is not provided\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (optval_auth_username && optval_auth_password) {
        socks5_usrpwd_request_make(optval_auth_username, optval_auth_password);
    }

    build_socket_addr(AF_INET, &g_bind_skaddr4, g_bind_ipstr4, g_bind_portno);
    build_socket_addr(AF_INET6, &g_bind_skaddr6, g_bind_ipstr6, g_bind_portno);
    build_socket_addr(get_ipstr_family(g_server_ipstr), &g_server_skaddr, g_server_ipstr, g_server_portno);
    if (g_options & OPT_ENABLE_FAKEDNS) {
        build_socket_addr(AF_INET, &g_fakedns_skaddr, g_fakedns_ipstr, g_fakedns_portno);
    }
    return;

PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    setvbuf(stdout, NULL, _IOLBF, 256);
    parse_command_args(argc, argv);

    LOG_ALWAYS_INF("[main] server address: %s#%hu", g_server_ipstr, g_server_portno);
    if (g_options & OPT_ENABLE_IPV4) LOG_ALWAYS_INF("[main] listen address: %s#%hu", g_bind_ipstr4, g_bind_portno);
    if (g_options & OPT_ENABLE_IPV6) LOG_ALWAYS_INF("[main] listen address: %s#%hu", g_bind_ipstr6, g_bind_portno);
    if (g_tcp_syncnt_max) LOG_ALWAYS_INF("[main] max number of syn retries: %hhu", g_tcp_syncnt_max);
    LOG_ALWAYS_INF("[main] udp cache capacity: main=%hu fork=%hu tproxy=%hu", 
                   lrucache_get_main_maxsize(), lrucache_get_fork_maxsize(), lrucache_get_tproxy_maxsize());
    LOG_ALWAYS_INF("[main] udp session idle timeout: %hu", g_udp_idletimeout_sec);
    LOG_ALWAYS_INF("[main] number of worker threads: %hhu", g_nthreads);
    LOG_ALWAYS_INF("[main] max file descriptor limit: %zu", get_nofile_limit());
    if (g_options & OPT_ENABLE_TCP) LOG_ALWAYS_INF("[main] enable tcp transparent proxy");
    if (g_options & OPT_ENABLE_UDP) LOG_ALWAYS_INF("[main] enable udp transparent proxy");
    if (g_options & OPT_TCP_USE_REDIRECT) LOG_ALWAYS_INF("[main] use redirect instead of tproxy");
    if (g_options & OPT_ALWAYS_REUSE_PORT) LOG_ALWAYS_INF("[main] always enable reuseport feature");
    if (g_options & OPT_ENABLE_TFO_ACCEPT) LOG_ALWAYS_INF("[main] enable tfo for tcp server socket");
    if (g_options & OPT_ENABLE_TFO_CONNECT) LOG_ALWAYS_INF("[main] enable tfo for tcp client socket");
    if (g_options & OPT_ENABLE_FAKEDNS) {
        LOG_ALWAYS_INF("[main] enable fakedns feature");
        LOG_ALWAYS_INF("[main] fakedns listen address: %s#%hu", g_fakedns_ipstr, g_fakedns_portno);
        fakedns_init(g_fakedns_cidr);
        if (g_fakedns_cache_path[0]) {
             LOG_ALWAYS_INF("[main] fakedns cache path: %s", g_fakedns_cache_path);
             fakedns_load(g_fakedns_cache_path);
        }
    }
    LOGINF("[main] verbose mode (affect performance)");

    g_thread_count = g_nthreads - 1;
    for (int i = 0; i < g_thread_count; ++i) {
        int ret = pthread_create(&g_threads[i].thread_id, NULL, run_event_loop, &g_threads[i]);
        if (ret != 0) {
            LOGERR("[main] create worker thread: %s", strerror(ret));
            return ret;
        }
    }
    run_event_loop(NULL);  // main thread passes NULL

    // Wait for all worker threads to exit
    for (int i = 0; i < g_thread_count; ++i) {
        pthread_join(g_threads[i].thread_id, NULL);
    }
    LOG_ALWAYS_INF("[main] all worker threads exited");

    LOG_ALWAYS_INF("[main] exiting...");
    if ((g_options & OPT_ENABLE_FAKEDNS) && g_fakedns_cache_path[0]) {
        fakedns_save(g_fakedns_cache_path);
    }

    return 0;
}

static void on_signal_read(evloop_t *loop, evio_t *watcher, int revents __attribute__((unused))) {
    struct signalfd_siginfo fdsi;
    ssize_t s = read(watcher->fd, &fdsi, sizeof(struct signalfd_siginfo));
    if (s != sizeof(struct signalfd_siginfo)) return;

    LOG_ALWAYS_INF("[on_signal_read] caught signal %d, stopping...", fdsi.ssi_signo);
    
    // Notify all worker threads to exit
    for (int i = 0; i < g_thread_count; i++) {
        if (g_threads[i].evloop) {
            ev_async_send(g_threads[i].evloop, &g_threads[i].exit_watcher);
        }
    }
    
    ev_break(loop, EVBREAK_ALL);
}

// Async watcher callback for worker threads to receive exit notification
static void on_async_exit(evloop_t *loop, ev_async *watcher __attribute__((unused)), int revents __attribute__((unused))) {
    ev_break(loop, EVBREAK_ALL);
}

static void* run_event_loop(void *arg) {
    thread_info_t *thread_info = (thread_info_t *)arg;
    bool is_main_thread = (thread_info == NULL);
    
    evloop_t *evloop = ev_loop_new(0);
    
    /* Resource tracking for cleanup */
    int exit_code = 0;
    int signalfd_fd = -1;
    evio_t *tcp4_watcher = NULL, *tcp6_watcher = NULL;
    evio_t *udp4_watcher = NULL, *udp6_watcher = NULL;
    evio_t *fakedns_watcher = NULL;
    int tcp4_sockfd = -1, tcp6_sockfd = -1;
    int udp4_sockfd = -1, udp6_sockfd = -1;
    int fakedns_sockfd = -1;
    
    // Register async watcher for worker threads to receive exit notification
    if (!is_main_thread) {
        thread_info->evloop = evloop;
        ev_async_init(&thread_info->exit_watcher, on_async_exit);
        ev_async_start(evloop, &thread_info->exit_watcher);
    }

    /* Initialize memory pools (thread-local) */
    /* Context pool serves: Main table + Fork table + TProxy table */
    size_t cache_size = lrucache_get_main_maxsize() 
                      + lrucache_get_fork_maxsize()
                      + lrucache_get_tproxy_maxsize();
    size_t initial_blocks = cache_size;
    
    if (initial_blocks < MEMPOOL_INITIAL_SIZE) initial_blocks = MEMPOOL_INITIAL_SIZE;
    
    /* 1. Packet Pool (variable-sized, high limit for throughput) */
    g_udp_packet_pool = mempool_create(
        MEMPOOL_BLOCK_SIZE, 
        initial_blocks, 
        65536
    );
    if (!g_udp_packet_pool) {
        LOGERR("[run_event_loop] failed to create packet memory pool");
        exit_code = 1;
        goto cleanup;
    }

    /* 2. UDP Context Pool: serves udp_socks5ctx_t (264 bytes) and udp_tproxyctx_t (120 bytes)
     * Block size = max(sizeof(udp_socks5ctx_t), sizeof(udp_tproxyctx_t)) 
     * Note: udp_tproxyctx_t wastes ~54% per allocation, acceptable for reduced fragmentation */
    g_udp_context_pool = mempool_create(
        sizeof(udp_socks5ctx_t),  /* 264 bytes (larger of the two) */
        initial_blocks, 
        initial_blocks * 2
    );
    if (!g_udp_context_pool) {
        LOGERR("[run_event_loop] failed to create context memory pool");
        exit_code = 1;
        goto cleanup;
    }
    
    /* TCP Context Pool */
    g_tcp_context_pool = mempool_create(
        sizeof(tcp_context_t),
        128,
        0
    );
    if (!g_tcp_context_pool) {
        LOGERR("[run_event_loop] failed to create tcp context memory pool");
        exit_code = 1;
        goto cleanup;
    }

    if (is_main_thread) {
         sigset_t mask;
         sigemptyset(&mask);
         sigaddset(&mask, SIGINT);
         sigaddset(&mask, SIGTERM);
         signalfd_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
         if (signalfd_fd < 0) {
             LOGERR("[run_event_loop] signalfd: %s", strerror(errno));
             exit_code = errno;
             goto cleanup;
         }
         
         static evio_t signal_watcher;
         ev_io_init(&signal_watcher, on_signal_read, signalfd_fd, EV_READ);
         ev_io_start(evloop, &signal_watcher);
    }
    
    if (g_options & OPT_ENABLE_TCP) {
        bool is_tproxy = !(g_options & OPT_TCP_USE_REDIRECT);
        bool is_tfo_accept = g_options & OPT_ENABLE_TFO_ACCEPT;
        bool is_reuse_port = g_nthreads > 1 || (g_options & OPT_ALWAYS_REUSE_PORT);

        if (g_options & OPT_ENABLE_IPV4) {
            tcp4_sockfd = new_tcp_listen_sockfd(AF_INET, is_tproxy, is_reuse_port, is_tfo_accept);

            if (bind(tcp4_sockfd, (void *)&g_bind_skaddr4, sizeof(skaddr4_t)) < 0) {
                LOGERR("[run_event_loop] bind tcp4 address: %s", strerror(errno));
                exit_code = errno;
                goto cleanup;
            }
            if (listen(tcp4_sockfd, SOMAXCONN) < 0) {
                LOGERR("[run_event_loop] listen tcp4 socket: %s", strerror(errno));
                exit_code = errno;
                goto cleanup;
            }

            tcp4_watcher = malloc(sizeof(*tcp4_watcher));
            if (!tcp4_watcher) {
                LOGERR("[run_event_loop] malloc tcp4_watcher failed");
                exit_code = ENOMEM;
                goto cleanup;
            }
            tcp4_watcher->data = (void *)1;
            ev_io_init(tcp4_watcher, tcp_tproxy_accept_cb, tcp4_sockfd, EV_READ);
            ev_io_start(evloop, tcp4_watcher);
        }

        if (g_options & OPT_ENABLE_IPV6) {
            tcp6_sockfd = new_tcp_listen_sockfd(AF_INET6, is_tproxy, is_reuse_port, is_tfo_accept);

            if (bind(tcp6_sockfd, (void *)&g_bind_skaddr6, sizeof(skaddr6_t)) < 0) {
                LOGERR("[run_event_loop] bind tcp6 address: %s", strerror(errno));
                exit_code = errno;
                goto cleanup;
            }
            if (listen(tcp6_sockfd, SOMAXCONN) < 0) {
                LOGERR("[run_event_loop] listen tcp6 socket: %s", strerror(errno));
                exit_code = errno;
                goto cleanup;
            }

            tcp6_watcher = malloc(sizeof(*tcp6_watcher));
            if (!tcp6_watcher) {
                LOGERR("[run_event_loop] malloc tcp6_watcher failed");
                exit_code = ENOMEM;
                goto cleanup;
            }
            tcp6_watcher->data = NULL;
            ev_io_init(tcp6_watcher, tcp_tproxy_accept_cb, tcp6_sockfd, EV_READ);
            ev_io_start(evloop, tcp6_watcher);
        }
    }

    if (g_options & OPT_ENABLE_UDP) {
        bool is_reuse_port = g_nthreads > 1 || (g_options & OPT_ALWAYS_REUSE_PORT);

        if (g_options & OPT_ENABLE_IPV4) {
            udp4_sockfd = new_udp_tprecv_sockfd(AF_INET, is_reuse_port);

            if (bind(udp4_sockfd, (void *)&g_bind_skaddr4, sizeof(skaddr4_t)) < 0) {
                LOGERR("[run_event_loop] bind udp4 address: %s", strerror(errno));
                exit_code = errno;
                goto cleanup;
            }

            udp4_watcher = malloc(sizeof(*udp4_watcher));
            if (!udp4_watcher) {
                LOGERR("[run_event_loop] malloc udp4_watcher failed");
                exit_code = ENOMEM;
                goto cleanup;
            }
            udp4_watcher->data = (void *)1;
            ev_io_init(udp4_watcher, udp_tproxy_recvmsg_cb, udp4_sockfd, EV_READ);
            ev_io_start(evloop, udp4_watcher);
        }

        if (g_options & OPT_ENABLE_IPV6) {
            udp6_sockfd = new_udp_tprecv_sockfd(AF_INET6, is_reuse_port);

            if (bind(udp6_sockfd, (void *)&g_bind_skaddr6, sizeof(skaddr6_t)) < 0) {
                LOGERR("[run_event_loop] bind udp6 address: %s", strerror(errno));
                exit_code = errno;
                goto cleanup;
            }

            udp6_watcher = malloc(sizeof(*udp6_watcher));
            if (!udp6_watcher) {
                LOGERR("[run_event_loop] malloc udp6_watcher failed");
                exit_code = ENOMEM;
                goto cleanup;
            }
            udp6_watcher->data = NULL;
            ev_io_init(udp6_watcher, udp_tproxy_recvmsg_cb, udp6_sockfd, EV_READ);
            ev_io_start(evloop, udp6_watcher);
        }
    }

    if ((g_options & OPT_ENABLE_FAKEDNS) && is_main_thread) {
        fakedns_sockfd = new_udp_normal_sockfd(AF_INET);
        if (bind(fakedns_sockfd, (void *)&g_fakedns_skaddr, sizeof(skaddr4_t)) < 0) {
            LOGERR("[run_event_loop] bind fakedns address: %s", strerror(errno));
            exit_code = errno;
            goto cleanup;
        }
        fakedns_watcher = malloc(sizeof(*fakedns_watcher));
        if (!fakedns_watcher) {
            LOGERR("[run_event_loop] malloc fakedns_watcher failed");
            exit_code = ENOMEM;
            goto cleanup;
        }
        ev_io_init(fakedns_watcher, udp_dns_recv_cb, fakedns_sockfd, EV_READ);
        ev_io_start(evloop, fakedns_watcher);
    }

    ev_run(evloop, 0);

cleanup:
    /* 1. Stop all IO watchers to prevent events during cleanup */
    if (tcp4_watcher) { ev_io_stop(evloop, tcp4_watcher); free(tcp4_watcher); tcp4_watcher = NULL; }
    if (tcp6_watcher) { ev_io_stop(evloop, tcp6_watcher); free(tcp6_watcher); tcp6_watcher = NULL; }
    if (udp4_watcher) { ev_io_stop(evloop, udp4_watcher); free(udp4_watcher); udp4_watcher = NULL; }
    if (udp6_watcher) { ev_io_stop(evloop, udp6_watcher); free(udp6_watcher); udp6_watcher = NULL; }
    if (fakedns_watcher) { ev_io_stop(evloop, fakedns_watcher); free(fakedns_watcher); fakedns_watcher = NULL; }
    
    /* 2. Close sockets */
    if (tcp4_sockfd >= 0) { close(tcp4_sockfd); tcp4_sockfd = -1; }
    if (tcp6_sockfd >= 0) { close(tcp6_sockfd); tcp6_sockfd = -1; }
    if (udp4_sockfd >= 0) { close(udp4_sockfd); udp4_sockfd = -1; }
    if (udp6_sockfd >= 0) { close(udp6_sockfd); udp6_sockfd = -1; }
    if (fakedns_sockfd >= 0) { close(fakedns_sockfd); fakedns_sockfd = -1; }
    if (signalfd_fd >= 0) { close(signalfd_fd); signalfd_fd = -1; }
    
    /* 3. Return all active sessions to pools */
    if (g_options & OPT_ENABLE_UDP) udp_proxy_close_all_sessions(evloop);
    if (g_options & OPT_ENABLE_TCP) tcp_proxy_close_all_sessions(evloop);
    
    /* 4. Destroy memory pools */
    if (g_udp_packet_pool) {
        size_t leaks = mempool_destroy(g_udp_packet_pool);
        if (leaks > 0) LOGERR("[run_event_loop] packet pool leaks: %zu", leaks);
        g_udp_packet_pool = NULL;
    }
    if (g_udp_context_pool) {
        size_t leaks = mempool_destroy(g_udp_context_pool);
        if (leaks > 0) LOGERR("[run_event_loop] udp context pool leaks: %zu", leaks);
        g_udp_context_pool = NULL;
    }
    if (g_tcp_context_pool) {
        size_t leaks = mempool_destroy(g_tcp_context_pool);
        if (leaks > 0) LOGERR("[run_event_loop] tcp context pool leaks: %zu", leaks);
        g_tcp_context_pool = NULL;
    }
    
    /* 5. Destroy event loop */
    if (evloop) ev_loop_destroy(evloop);
    
    if (exit_code != 0) exit(exit_code);
    return NULL;
}
