/*
 * hashcrack.c
 * -----------
 * Hash cracker — MD5, SHA1, SHA256, SHA512, NTHash
 * Methods: wordlist + brute force
 *
 * Build:
 *   gcc -O2 -o hashcrack hashcrack.c -lssl -lcrypto
 *
 * Usage:
 *   ./hashcrack -h <hash> -t <type> -w <wordlist>
 *   ./hashcrack -h <hash> -t <type> -b -c <charset> -l <maxlen>
 *
 * Types: md5, sha1, sha256, sha512, ntlm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/* ── colours ── */
#define RED     "\033[0;31m"
#define GREEN   "\033[0;32m"
#define YELLOW  "\033[0;33m"
#define CYAN    "\033[0;36m"
#define GREY    "\033[0;90m"
#define RESET   "\033[0m"

#define MAX_WORD_LEN  256
#define MAX_HASH_LEN  129

/* ── hash type enum ── */
typedef enum { T_MD5, T_SHA1, T_SHA256, T_SHA512, T_NTLM } HashType;

/* ── helpers ── */
static void bytes_to_hex(const unsigned char *b, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", b[i]);
    out[len * 2] = '\0';
}

static void str_tolower(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

/* ── NTLM (MD4 over UTF-16LE) ── */
static void ntlm_hash(const char *password, char *out_hex) {
    size_t len = strlen(password);
    unsigned char *utf16 = malloc(len * 2);
    if (!utf16) { out_hex[0] = '\0'; return; }

    for (size_t i = 0; i < len; i++) {
        utf16[i * 2]     = (unsigned char)password[i];
        utf16[i * 2 + 1] = 0x00;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md4 = EVP_md4();
    unsigned char digest[16];
    unsigned int dlen = 16;

    EVP_DigestInit_ex(ctx, md4, NULL);
    EVP_DigestUpdate(ctx, utf16, len * 2);
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    free(utf16);

    bytes_to_hex(digest, 16, out_hex);
}

/* ── compute hash of word ── */
static void compute_hash(const char *word, HashType type, char *out_hex) {
    unsigned char digest[64];

    switch (type) {
        case T_MD5: {
            MD5((const unsigned char *)word, strlen(word), digest);
            bytes_to_hex(digest, 16, out_hex);
            break;
        }
        case T_SHA1: {
            SHA1((const unsigned char *)word, strlen(word), digest);
            bytes_to_hex(digest, 20, out_hex);
            break;
        }
        case T_SHA256: {
            SHA256((const unsigned char *)word, strlen(word), digest);
            bytes_to_hex(digest, 32, out_hex);
            break;
        }
        case T_SHA512: {
            SHA512((const unsigned char *)word, strlen(word), digest);
            bytes_to_hex(digest, 64, out_hex);
            break;
        }
        case T_NTLM: {
            ntlm_hash(word, out_hex);
            break;
        }
    }
}

/* ── wordlist attack ── */
static int wordlist_attack(const char *target, HashType type, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, RED "[!] Cannot open wordlist: %s\n" RESET, path);
        return 0;
    }

    printf(CYAN "[*] Wordlist attack → %s\n" RESET, path);

    char word[MAX_WORD_LEN];
    char computed[MAX_HASH_LEN];
    long count = 0;

    while (fgets(word, sizeof(word), f)) {
        /* strip newline */
        size_t wlen = strlen(word);
        if (wlen > 0 && word[wlen - 1] == '\n') word[--wlen] = '\0';
        if (wlen > 0 && word[wlen - 1] == '\r') word[--wlen] = '\0';
        if (wlen == 0) continue;

        compute_hash(word, type, computed);
        count++;

        if (count % 100000 == 0)
            printf(GREY "\r[*] Tried %ld words..." RESET, count);

        if (strcmp(computed, target) == 0) {
            fclose(f);
            printf(GREEN "\n[+] CRACKED after %ld attempts\n" RESET, count);
            printf(GREEN "[+] Hash   : %s\n" RESET, target);
            printf(GREEN "[+] Plain  : %s\n" RESET, word);
            return 1;
        }
    }

    fclose(f);
    printf(YELLOW "\n[-] Not found in wordlist (%ld words tried)\n" RESET, count);
    return 0;
}

/* ── brute force (recursive) ── */
static int bf_found = 0;
static char bf_result[MAX_WORD_LEN];

static void brute_recurse(char *buf, int pos, int maxlen,
                           const char *charset, int cslen,
                           const char *target, HashType type,
                           long *count) {
    if (bf_found) return;

    char computed[MAX_HASH_LEN];
    compute_hash(buf, type, computed);
    (*count)++;

    if (*count % 500000 == 0)
        printf(GREY "\r[*] Tried %ld combinations... current: %-20s" RESET, *count, buf);

    if (strcmp(computed, target) == 0) {
        bf_found = 1;
        strncpy(bf_result, buf, MAX_WORD_LEN - 1);
        return;
    }

    if (pos >= maxlen) return;

    for (int i = 0; i < cslen; i++) {
        buf[pos] = charset[i];
        buf[pos + 1] = '\0';
        brute_recurse(buf, pos + 1, maxlen, charset, cslen, target, type, count);
        if (bf_found) return;
    }
}

static int brute_attack(const char *target, HashType type,
                        const char *charset, int maxlen) {
    printf(CYAN "[*] Brute force attack | charset: %s | maxlen: %d\n" RESET, charset, maxlen);

    char buf[MAX_WORD_LEN];
    long count = 0;
    int cslen = (int)strlen(charset);

    for (int len = 1; len <= maxlen; len++) {
        printf(GREY "[*] Trying length %d...\n" RESET, len);
        memset(buf, 0, sizeof(buf));
        brute_recurse(buf, 0, len, charset, cslen, target, type, &count);
        if (bf_found) break;
    }

    if (bf_found) {
        printf(GREEN "\n[+] CRACKED after %ld attempts\n" RESET, count);
        printf(GREEN "[+] Hash   : %s\n" RESET, target);
        printf(GREEN "[+] Plain  : %s\n" RESET, bf_result);
        return 1;
    }

    printf(YELLOW "\n[-] Not found via brute force (%ld tried)\n" RESET, count);
    return 0;
}

/* ── auto-detect hash type by length ── */
static HashType detect_type(const char *hash) {
    switch (strlen(hash)) {
        case 32:  return T_MD5;
        case 40:  return T_SHA1;
        case 64:  return T_SHA256;
        case 128: return T_SHA512;
        default:
            fprintf(stderr, YELLOW "[?] Unknown hash length, defaulting to MD5\n" RESET);
            return T_MD5;
    }
}

static const char *type_name(HashType t) {
    switch (t) {
        case T_MD5:    return "MD5";
        case T_SHA1:   return "SHA1";
        case T_SHA256: return "SHA256";
        case T_SHA512: return "SHA512";
        case T_NTLM:   return "NTLM";
    }
    return "?";
}

/* ── usage ── */
static void usage(const char *prog) {
    printf("\n  " CYAN "hashcrack" RESET " — by r46w\n\n");
    printf("  " GREY "wordlist mode:\n" RESET);
    printf("    %s -h <hash> [-t <type>] -w <wordlist>\n\n", prog);
    printf("  " GREY "brute force mode:\n" RESET);
    printf("    %s -h <hash> [-t <type>] -b [-c <charset>] [-l <maxlen>]\n\n", prog);
    printf("  " GREY "options:\n" RESET);
    printf("    -h  hash to crack\n");
    printf("    -t  hash type: md5 sha1 sha256 sha512 ntlm (auto-detect if omitted)\n");
    printf("    -w  wordlist path\n");
    printf("    -b  brute force mode\n");
    printf("    -c  charset for brute force (default: abcdefghijklmnopqrstuvwxyz0123456789)\n");
    printf("    -l  max length for brute force (default: 6)\n\n");
}

/* ── main ── */
int main(int argc, char *argv[]) {
    char *hash      = NULL;
    char *type_str  = NULL;
    char *wordlist  = NULL;
    char *charset   = "abcdefghijklmnopqrstuvwxyz0123456789";
    int   brute     = 0;
    int   maxlen    = 6;

    if (argc < 2) { usage(argv[0]); return 1; }

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "-h") && i+1 < argc) hash      = argv[++i];
        else if (!strcmp(argv[i], "-t") && i+1 < argc) type_str  = argv[++i];
        else if (!strcmp(argv[i], "-w") && i+1 < argc) wordlist  = argv[++i];
        else if (!strcmp(argv[i], "-c") && i+1 < argc) charset   = argv[++i];
        else if (!strcmp(argv[i], "-l") && i+1 < argc) maxlen    = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-b"))                brute     = 1;
    }

    if (!hash) {
        fprintf(stderr, RED "[!] No hash provided (-h)\n" RESET);
        usage(argv[0]);
        return 1;
    }

    /* lowercase hash */
    char hash_lc[MAX_HASH_LEN];
    strncpy(hash_lc, hash, MAX_HASH_LEN - 1);
    hash_lc[MAX_HASH_LEN - 1] = '\0';
    str_tolower(hash_lc);

    /* determine type */
    HashType type;
    if (type_str) {
        if      (!strcasecmp(type_str, "md5"))    type = T_MD5;
        else if (!strcasecmp(type_str, "sha1"))   type = T_SHA1;
        else if (!strcasecmp(type_str, "sha256")) type = T_SHA256;
        else if (!strcasecmp(type_str, "sha512")) type = T_SHA512;
        else if (!strcasecmp(type_str, "ntlm"))   type = T_NTLM;
        else {
            fprintf(stderr, RED "[!] Unknown type: %s\n" RESET, type_str);
            return 1;
        }
    } else {
        type = detect_type(hash_lc);
    }

    printf("\n  " CYAN "hashcrack" RESET " — by r46w\n");
    printf("  " GREY "hash  : %s\n" RESET, hash_lc);
    printf("  " GREY "type  : %s\n\n" RESET, type_name(type));

    int cracked = 0;

    if (wordlist)
        cracked = wordlist_attack(hash_lc, type, wordlist);

    if (!cracked && brute)
        cracked = brute_attack(hash_lc, type, charset, maxlen);

    if (!cracked)
        printf(RED "\n[!] Hash not cracked.\n\n" RESET);
    else
        printf("\n");

    return cracked ? 0 : 1;
}
