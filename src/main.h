#ifndef TRAFFIC_ANALYZER_MAIN_H
#define TRAFFIC_ANALYZER_MAIN_H

typedef enum {
    SYN_SENT = 1,
    SYN_ACK_RECEIVED,
    ESTABLISHED,
} tcp_session_state_t;

typedef enum {
    DIRECT,
    REVERSE,
} src_dst_direction_t;

typedef enum {
    STD_OUT,
    OUT_FILE,
    BOTH,
} output_dst_t;

typedef union {
    long pc;
    struct {
        uint16_t p;
        uint16_t c;
    };
} port_count_t;

#define ARROW_DELIMITER_STR " -> "

#define SNAP_LEN 1518

#define PRINTF_FORMAT_LEN               10 + 1    // "%.15s:%d%s" + '\0'
#define IP_ADDR_LEN                     15 + 1    // "255.255.255.255" + '\0'
#define SUCCESS_HASH_TABLE_KEY_LEN      46 + 1    // "255.255.255.255:12345 -> 255.255.255.255:12345" + '\0'
#define FAILED_HASH_TABLE_KEY_LEN       40 + 1    // "255.255.255.255 -> 255.255.255.255:12345" + '\0'
#define FAILED_HASH_TABLE_KEY_FULL_LEN  46 + 1    // "255.255.255.255:12345 -> 255.255.255.255:12345" + '\0'

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"

#define BYTE_TO_BINARY(byte) \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')

#define TCP_FLAGS_TO_CHARS(byte) \
  (byte & 0x80 ? 'C' : '.'), \
  (byte & 0x40 ? 'E' : '.'), \
  (byte & 0x20 ? 'U' : '.'), \
  (byte & 0x10 ? 'A' : '.'), \
  (byte & 0x08 ? 'P' : '.'), \
  (byte & 0x04 ? 'R' : '.'), \
  (byte & 0x02 ? 'S' : '.'), \
  (byte & 0x01 ? 'F' : '.')

void parse_options(int argc, char **argv);
void print_app_usage(void);

void printf_debug(const char *format, ...);
void tee(FILE *f, char const *fmt, ...);

void sig_handler(int sig);
void cleanup();

void timer_callback(int sig);
void start_timer(void);

char* generate_success_hash_table_key(char *success_hash_table_key, const struct ip *ip,const struct tcphdr *tcp,
                                      src_dst_direction_t src_dst_direction);
char* generate_failed_hash_table_key(char *failed_hash_table_key, const struct ip *ip, const struct tcphdr *tcp);
char* generate_failed_hash_table_key_full(char *failed_hash_table_key_full, const char *failed_hash_table_key,
                                          uint16_t port);

void process_tcp_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void process_syn(char *success_hash_table_key, char *failed_hash_table_key, uint16_t th_sport);
void process_syn_ack(char *success_hash_table_key, char *failed_hash_table_key);
void process_ack(char *success_hash_table_key, char *failed_hash_table_key);

void add_tcp_session_to_success_list(char *success_hash_table_key);
void add_tcp_session_to_failed_list(char *failed_hash_table_key, uint16_t th_sport);
void update_tcp_session_in_success_list(char *success_hash_table_key, char *failed_hash_table_key);
void remove_tcp_session_from_success_list(const char *success_hash_table_key);
void remove_tcp_session_from_failed_list(char *failed_hash_table_key);

void print_success_message(const char *success_hash_table_key);
void print_failed_message(const char *failed_hash_table_key, const char *failed_hash_table_value);

void print_failed_hash_table();
void print_failed_hash_table_element (gpointer key, gpointer value, gpointer user_data);

void print_hash_tables();
void print_hash_table(GHashTable *hash_table);
void print_hash_table_element (gpointer key, gpointer value, gpointer user_data);

#endif //TRAFFIC_ANALYZER_MAIN_H
