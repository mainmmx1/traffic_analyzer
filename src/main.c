#include <glib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "main.h"

char *dev = "any";
int all_interfaces = 1;

char *out_file_name = NULL;
FILE *out_file = NULL;
output_dst_t output_dst = STD_OUT;

int debug_enabled = 0;

GHashTable* success_hash_table = NULL;
GHashTable* failed_hash_table = NULL;

pcap_t *handle;
struct bpf_program fp;

timer_t timer_id;
pthread_mutex_t lock_hash_tables = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    success_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    failed_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    parse_options(argc, argv);

    if (out_file_name) {
        out_file = fopen(out_file_name, "w");
    }

    if (-1 == pcap_lookupnet(dev, &net, &mask, errbuf)) {
        printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, SNAP_LEN, 1, 100, errbuf);
    if (NULL == handle) {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    if (-1 == pcap_compile(handle, &fp, filter_exp, 0, net)) {
        printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (-1 == pcap_setfilter(handle, &fp)) {
        printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    signal(SIGALRM, timer_callback);
    start_timer();

    pcap_loop(handle, 0, process_tcp_packet, NULL);

    cleanup();

    exit(EXIT_SUCCESS);
}

void parse_options(int argc, char **argv) {
    int opt = 0;

    while (-1 != (opt = getopt(argc, argv, "i:aw:bdh"))) {
        switch (opt) {
            case 'i':
                dev = optarg;
                all_interfaces = 0;
                break;
            case 'a':
                dev = "any";
                all_interfaces = 1;
                break;
            case 'w':
                out_file_name = optarg;
                output_dst = OUT_FILE;
                break;
            case 'b':
                output_dst = BOTH;
                break;
            case 'd':
                debug_enabled = 1;
                break;
            case 'h':
            default:
                print_app_usage();
                exit(EXIT_FAILURE);
        }
    }

    printf_debug("dev = %s\n", dev);
    printf_debug("all_interfaces = %d\n", all_interfaces);
    printf_debug("out_file_name = %s\n", out_file_name);
    printf_debug("output_dst = %d\n", output_dst);
    printf_debug("debug_enabled = %d\n", debug_enabled);
}

void print_app_usage(void) {
    printf("Usage: traffic_analyzer [options]\n");
    printf("Options:\n");
    printf("\t-i <interface>\tListen on <interface> for packets. If not set then \"any\" interface will be used.\n");
    printf("\t-a\t\tListen on any interface for packets explicitly.\n");
    printf("\t-w <file>\tWrite output to <file>. If not set then stdout will be used.\n");
    printf("\t-b\t\tWrite output both to stdout and file.\n");
    printf("\t-d\t\tPrint debug info.\n");
    printf("\t-h\t\tPrint this help and exit.\n");
    printf("\n");
}

void printf_debug(const char *format, ...) {
    if (debug_enabled) {
        va_list args;
        va_start(args, format);

        vprintf(format, args);

        va_end(args);
    }
}

void sig_handler(int sig) {
    printf("\nCapture complete.\n");

    cleanup();

    exit(EXIT_SUCCESS);
}

void cleanup() {
    pcap_freecode(&fp);
    pcap_close(handle);

    g_hash_table_destroy(success_hash_table);
    g_hash_table_destroy(failed_hash_table);

    if (out_file)
        fclose(out_file);
}

void timer_callback(int sig) {
    printf_debug("Timer callback\n");

    pthread_mutex_lock(&lock_hash_tables);

    print_failed_hash_table();
    g_hash_table_remove_all(failed_hash_table);

    pthread_mutex_unlock(&lock_hash_tables);
}

void print_failed_hash_table() {
    g_hash_table_foreach(failed_hash_table, print_failed_hash_table_element, NULL);
}

void print_failed_hash_table_element (gpointer key, gpointer value, gpointer user_data) {
    print_failed_message(key, value);
}

void print_failed_message(const char *failed_hash_table_key, const char *failed_hash_table_value) {
    port_count_t port_count;
    port_count.pc = (long)failed_hash_table_value;

    char failed_hash_table_key_full[FAILED_HASH_TABLE_KEY_FULL_LEN] = "";

    if (1 == port_count.c) {
        tee(out_file, "FAILED  %s\n",
            generate_failed_hash_table_key_full(failed_hash_table_key_full, failed_hash_table_key, port_count.p));
    } else {
        tee(out_file, "FAILED  %s (count: %d)\n", failed_hash_table_key, port_count.c);
    }

}

void tee(FILE *f, char const *fmt, ...) {
    va_list ap;

    if (STD_OUT == output_dst || BOTH == output_dst) {
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }

    if (OUT_FILE == output_dst || BOTH == output_dst) {
        if (out_file && f) {
            va_start(ap, fmt);
            vfprintf(f, fmt, ap);
            va_end(ap);
            fflush(f);
        }
    }
}

void start_timer(void) {
    struct itimerspec value;

    value.it_value.tv_sec = 1;
    value.it_value.tv_nsec = 0;

    value.it_interval.tv_sec = 1;
    value.it_interval.tv_nsec = 0;

    timer_create (CLOCK_REALTIME, NULL, &timer_id);

    timer_settime (timer_id, 0, &value, NULL);
}

void process_tcp_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf_debug("process_tcp_packet() \n");

    pthread_mutex_lock(&lock_hash_tables);

    const struct ether_header *ethernet = (struct ether_header *)packet;
    const struct ip *ip = (struct ip*)((u_char *)ethernet + (all_interfaces ? SLL_HDR_LEN : sizeof(struct ether_header)));
    const struct tcphdr *tcp = (struct tcphdr*)((u_char *)ip + sizeof(struct ip));

    char *success_hash_table_key_direct = malloc(SUCCESS_HASH_TABLE_KEY_LEN);
    char *success_hash_table_key_reverse = malloc(SUCCESS_HASH_TABLE_KEY_LEN);
    char *failed_hash_table_key = malloc(FAILED_HASH_TABLE_KEY_LEN);

    generate_success_hash_table_key(success_hash_table_key_direct, ip, tcp, DIRECT);
    generate_success_hash_table_key(success_hash_table_key_reverse, ip, tcp, REVERSE);
    generate_failed_hash_table_key(failed_hash_table_key, ip, tcp);

    printf_debug("success_hash_table_key_direct = %s\n", success_hash_table_key_direct);
    printf_debug("success_hash_table_key_reverse = %s\n", success_hash_table_key_reverse);
    printf_debug("failed_hash_table_key = %s\n", failed_hash_table_key);

    switch (tcp->th_flags) {
        case TH_SYN:
            process_syn(success_hash_table_key_direct, failed_hash_table_key, ntohs(tcp->th_sport));
            break;
        case (TH_SYN | TH_ACK):
            process_syn_ack(success_hash_table_key_reverse, NULL);
            break;
        case TH_ACK:
            process_ack(success_hash_table_key_direct, failed_hash_table_key);
            break;
        default:
            printf_debug("default case TCP flags are: %d " BYTE_TO_BINARY_PATTERN " " BYTE_TO_BINARY_PATTERN "\n",
                         tcp->th_flags, BYTE_TO_BINARY(tcp->th_flags), TCP_FLAGS_TO_CHARS(tcp->th_flags));
            break;
    }

    if(debug_enabled) {
        print_hash_tables();
    }

    pthread_mutex_unlock(&lock_hash_tables);
}

char* generate_success_hash_table_key(char *success_hash_table_key, const struct ip *ip,
                                      const struct tcphdr *tcp, src_dst_direction_t src_dst_direction) {
    memset(success_hash_table_key, 0, SUCCESS_HASH_TABLE_KEY_LEN);

    if (DIRECT == src_dst_direction) {
        snprintf(success_hash_table_key, IP_ADDR_LEN, "%s", inet_ntoa(ip->ip_src));

        snprintf(success_hash_table_key + strlen(success_hash_table_key),
                 SUCCESS_HASH_TABLE_KEY_LEN - strlen(success_hash_table_key),
                 ":%d -> %s:%d",
                 ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
    } else {
        snprintf(success_hash_table_key, IP_ADDR_LEN, "%s", inet_ntoa(ip->ip_dst));

        snprintf(success_hash_table_key + strlen(success_hash_table_key),
                 SUCCESS_HASH_TABLE_KEY_LEN - strlen(success_hash_table_key),
                 ":%d -> %s:%d",
                 ntohs(tcp->th_dport), inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
    }

    return success_hash_table_key;
}

char* generate_failed_hash_table_key(char *failed_hash_table_key, const struct ip *ip, const struct tcphdr *tcp) {
    memset(failed_hash_table_key, 0, FAILED_HASH_TABLE_KEY_LEN);

    snprintf(failed_hash_table_key, FAILED_HASH_TABLE_KEY_LEN,
             "%s -> %s:%d", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

    return failed_hash_table_key;
}

char* generate_failed_hash_table_key_full(char *failed_hash_table_key_full, const char *failed_hash_table_key,
                                          uint16_t port) {
    int src_ip_len = strstr(failed_hash_table_key, ARROW_DELIMITER_STR) - failed_hash_table_key;

    char format[PRINTF_FORMAT_LEN] = "";
    snprintf(format, PRINTF_FORMAT_LEN, "%%.%ds:%%d%%s", src_ip_len);

    snprintf(failed_hash_table_key_full, FAILED_HASH_TABLE_KEY_FULL_LEN,
             format, failed_hash_table_key, port, failed_hash_table_key + src_ip_len);

    return failed_hash_table_key_full;
}

void process_syn(char *success_hash_table_key, char *failed_hash_table_key, uint16_t th_sport) {
    add_tcp_session_to_success_list(success_hash_table_key);
    add_tcp_session_to_failed_list(failed_hash_table_key, th_sport);
}

void add_tcp_session_to_success_list(char *success_hash_table_key) {
    gpointer value = g_hash_table_lookup(success_hash_table, success_hash_table_key);

    if (value) {
        printf_debug("ERROR: add_tcp_session_to_success_list() g_hash_table_lookup() found value %d for key %s",
                     value, success_hash_table_key);
    } else {
        g_hash_table_replace(success_hash_table, success_hash_table_key, (gpointer)SYN_SENT);
    }
}

void add_tcp_session_to_failed_list(char *failed_hash_table_key, uint16_t th_sport) {
    gpointer value = g_hash_table_lookup(failed_hash_table, failed_hash_table_key);

    port_count_t port_count;
    port_count.pc = (long)value;

    port_count.p = th_sport;
    port_count.c++;

    g_hash_table_replace(failed_hash_table, failed_hash_table_key, (gpointer)port_count.pc);
}

void process_syn_ack(char *success_hash_table_key, char *failed_hash_table_key) {
    update_tcp_session_in_success_list(success_hash_table_key, failed_hash_table_key);
}

void update_tcp_session_in_success_list(char *success_hash_table_key, char *failed_hash_table_key) {
    gpointer value = g_hash_table_lookup(success_hash_table, success_hash_table_key);

    switch ((long)value) {
        case SYN_SENT:
            g_hash_table_replace(success_hash_table, success_hash_table_key, (gpointer)SYN_ACK_RECEIVED);
            break;
        case SYN_ACK_RECEIVED:
            g_hash_table_replace(success_hash_table, success_hash_table_key, (gpointer)ESTABLISHED);
            print_success_message(success_hash_table_key);
            remove_tcp_session_from_success_list(success_hash_table_key);
            remove_tcp_session_from_failed_list(failed_hash_table_key);
            break;
        default:
            break;
    }
}

void print_success_message(const char *success_hash_table_key) {
    tee(out_file, "SUCCESS %s\n", success_hash_table_key);
}

void remove_tcp_session_from_success_list(const char *success_hash_table_key) {
    g_hash_table_remove(success_hash_table, success_hash_table_key);
}

void remove_tcp_session_from_failed_list(char *failed_hash_table_key) {
    if (!failed_hash_table_key)
        return;

    gpointer value = g_hash_table_lookup(failed_hash_table, failed_hash_table_key);

    port_count_t port_count;
    port_count.pc = (long)value;

    if (port_count.c > 1) {
        port_count.c--;
        g_hash_table_replace(failed_hash_table, failed_hash_table_key, (gpointer)port_count.pc);
    } else if (port_count.c == 1) {
        g_hash_table_remove(failed_hash_table, failed_hash_table_key);
    }
}

void process_ack(char *success_hash_table_key, char *failed_hash_table_key) {
    update_tcp_session_in_success_list(success_hash_table_key, failed_hash_table_key);
}

void print_hash_tables() {
    printf_debug("There are %d keys in the success_hash_table table:\n",
                 g_hash_table_size(success_hash_table));
    print_hash_table(success_hash_table);

    printf_debug("There are %d keys in the failed_hash_table table:\n",
                 g_hash_table_size(failed_hash_table));
    print_hash_table(failed_hash_table);
}

void print_hash_table(GHashTable *hash_table) {
    g_hash_table_foreach(hash_table, print_hash_table_element, NULL);
}

void print_hash_table_element (gpointer key, gpointer value, gpointer user_data) {
    printf_debug("%s %d\n", key, value);
}
