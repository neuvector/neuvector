#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "utils/helper.h"

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy (char *dst, const char *src, size_t siz)
{
    register char *d = dst;
    register const char *s = src;
    register size_t n = siz;

    /* Copy as many bytes as will fit */
    if (n != 0 && --n != 0) {
        do {
            if ((*d++ = *s++) == 0)
                break;
        } while (--n != 0);
    }

    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0) {
        if (siz != 0)
            *d = '\0';      /* NUL-terminate dst */
        while (s&&*s++)     /* avoid dereference a NUL pointer, get length of src*/
            ;
    }

    return(s - src - 1);    /* count does not include NUL */
}

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t strlcat (char *dst, const char *src, size_t siz)
{
    char *d = dst;
    const char *s = src;
    size_t n = siz;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end */
    while (n-- != 0 && *d != '\0')
        d++;
    dlen = d - dst;
    n = siz - dlen;

    if (n == 0)
        return(dlen + strlen(s));
    while (*s != '\0') {
        if (n != 1) {
            *d++ = *s;
            n--;
        }
        s++;
    }
    *d = '\0';

    return(dlen + (s - src));   /* count does not include NUL */
}

int count_cpu(void)
{
    FILE *fp;
    int n = 0, ret;

    fp = popen("nproc", "r");
    if (fp == NULL) {
        return 1;
    }

    ret = fscanf(fp, "%d", &n);
    pclose(fp);

    return ret > 0 ? n : 1;
}

static int8_t hex[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

int8_t c2hex(uint8_t c)
{
    return hex[c];
}

uint8_t *consume_string(uint8_t *ptr, int len)
{
    register uint8_t *l = ptr, *end = ptr + len;

    while (l < end) {
        if (unlikely(*l == '\0')) {
            return l;
        }

        l ++;
    }

    return NULL;
}

// eol_chars: return number of EOL characters. eg: if line ends with '\r\n', then 2.
uint8_t *consume_line(uint8_t *ptr, int len, int *eol_chars)
{
    register uint8_t *l = ptr, *end = ptr + len;
    register int n = 0;

    while (l < end) {
        if (unlikely(*l == '\r')) {
            n ++;
        } else if (unlikely(*l == '\n')) {
            *eol_chars = n + 1;
            return l + 1;
        } else {
            n = 0;
        }

        l ++;
    }

    *eol_chars = 0;
    return NULL;
}

void consume_tokens(uint8_t *ptr, int len, token_func_t func, void *param)
{
    register uint8_t *l = ptr, *end = ptr + len, *token = NULL;
    int idx = 0;

    while (l < end) {
        if (*l == ' ') {
            if (token != NULL) {
                int ret = func(param, token, l - token, idx);
                token = NULL;
                idx ++;

                if (ret == CONSUME_TOKEN_SKIP_LINE) {
                    return;
                }
            }
        } else if (token == NULL) {
            token = l;
        }

        l ++;
    }

    if (token != NULL) {
        func(param, token, l - token, idx);
    }
}

char *strip_str (char *s)
{
    int len;
    register char *start, *end, *ptr;

    if (s == NULL) {
        return NULL;
    }

    if ((len = strlen(s)) == 0) {
        return s;
    }

    // Remove leading spaces
    ptr = s;
    while (*ptr && (*ptr == '\n' || *ptr == '\r' ||
                    *ptr == '\t' || *ptr == ' ')) {
        ptr ++;
    }
    if (*ptr == '\0') {
        *s = '\0';
        return s;
    }
    start = ptr;

    // Remove trailing spaces
    ptr = s + len - 1;
    while (ptr >= start && (*ptr == '\n' || *ptr == '\r' ||
                            *ptr == '\t' || *ptr == ' ')) {
        ptr --;
    }
    end = ptr + 1;

    // Replace \r\n\t in the middle
    for (ptr = start; ptr < end; ptr ++) {
        if (*ptr == '\n' || *ptr == '\r' || *ptr == '\t') {
            *ptr = ' ';
        }
    }

    if (start == s) {
        *end = '\0';
    } else {
        strlcpy(s, start, end - start + 1);
    }

    return s;
}

static inline bool check_int_range (uint32_t *p, const char *v, int max)
{
    int value;
    char *end;

    value = strtol(v, &end, 10);
    if (*end != '\0' && *end != ':' && *end != '-') {
        return false;
    }

    if (value < 0 || value >= max) {
        return false;
    }

    *p = value;
    return true;
}


bool
parse_int_range (uint32_t *low, uint32_t *high, const char *range, int max)
{
    char *colon;

    *low = *high = 0;

    if (range == NULL || *range == '\0') {
        return false;
    }

    if ((colon = strchr(range, ':')) || (colon = strchr(range, '-'))) {
        if (!check_int_range(low, range, max)) {
            return false;
        }

        if (*(colon + 1) == '\0') {
            *high = DPI_MAX_PORTS - 1;
        } else if (!check_int_range(high, colon + 1, max)) {
            return false;
        }

        if (*low > *high) {
            return false;
        }
    } else {
        if (!check_int_range(low, range, max)) {
            return false;
        }
        *high = *low;
    }

    return true;
}

char *strip_str_quote (char *s)
{
    int len, i;

    if (s == NULL) {
        return NULL;
    }

    if ((len = strlen(s)) < 2) {
        return s;
    }

    if ((s[0] == '"' && s[len - 1] == '"') ||
        (s[0] == '\'' && s[len - 1] == '\'')) {
        s[len - 1] = '\0';
        for (i = 0; i < len - 1; i ++)
            s[i] = s[i + 1];
    }

    return s;
}

void free_split (char **tokens, int count)
{
    if (tokens) {
        while (count) {
            free(tokens[count - 1]);
            count --;
        }
        free(tokens);
    }
}

char **str_split (const char *s, const char *delim, int *count)
{
    char *str, *p, *token, *dummy;
    char **tokens;
    int i;

    *count = 0;

    if (s == NULL) {
        return NULL;
    }

    str = strdup(s);
    if (str == NULL) {
        return NULL;
    }

    p = str;
    token = strtok_r(p, delim, &dummy);
    while (token) {
        (*count) ++;
        token = strtok_r(NULL, delim, &dummy);
    }

    tokens = (char **)calloc(*count, sizeof(char *));
    if (tokens == NULL) {
        free(str);
        *count = 0;
        return NULL;
    }

    strcpy(str, s);
    p = str;
    i = 0;

    token = strtok_r(p, delim, &dummy);
    while (token) {
        tokens[i] = strdup(token);
        if (tokens[i] == NULL) {
            free_split(tokens, i);
            free(str);
            *count = 0;
            return NULL;
        }

        i ++;
        token = strtok_r(NULL, delim, &dummy);
    }

    free(str);
    return tokens;
}

void lower_string(char* s) {
   int c = 0;

   while (s[c] != '\0') {
      if (s[c] >= 'A' && s[c] <= 'Z') {
         s[c] = s[c] + 32;
      }
      c++;
   }
}
