#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>


#define SHA256_DIGEST_HEX_LENGTH    (SHA256_DIGEST_LENGTH * 2)
#define HMAC_DIGEST_MAX_HEX_LENGTH  (EVP_MAX_MD_SIZE * 2)

#define URI_ESCAPE_SLASH            ("%2F")

#define AMZ_DATE_MAX_LEN            (sizeof("YYYYmmdd"))
#define AMZ_DATE_TIME_MAX_LEN       (sizeof("YYYYmmddTHHMMSSZ"))

#define PRESIGN_AMZ_ARGS            ("X-Amz-Algorithm=AWS4-HMAC-SHA256"     \
    "&X-Amz-SignedHeaders=host&X-Amz-Credential=")
#define PRESIGN_AMZ_ARG_DATE        ("&X-Amz-Date=")
#define PRESIGN_AMZ_ARG_SIG         ("&X-Amz-Signature=")

#define PRESIGN_HOST_HEADER         ("host:")
#define PRESIGN_CANONICAL_SUFFIX    ("\nhost\nUNSIGNED-PAYLOAD")


static char *ngx_http_aws_auth_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_aws_auth_presign(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_aws_auth_preconfiguration(ngx_conf_t *cf);


typedef struct {
    ngx_str_t                  access_key;
    ngx_str_t                  secret_key;
    ngx_str_t                  service;
    ngx_str_t                  region;

    ngx_str_t                  secret_key_prefix;
    ngx_str_t                  signing_key_date;
    ngx_str_t                  signing_key;
    ngx_str_t                  key_scope;
    ngx_str_t                  key_scope_suffix;

    unsigned                   ignore:1;
} ngx_http_aws_auth_ctx_t;


typedef struct {
    ngx_http_aws_auth_ctx_t   *base;
    ngx_http_complex_value_t   url;
} ngx_http_aws_auth_presign_ctx_t;


typedef struct {
    ngx_str_t                  url;
    ngx_str_t                  host;
    ngx_str_t                  uri;
    ngx_str_t                  args;
} ngx_http_aws_auth_presign_parse_t;


typedef struct {
    ngx_conf_t                *cf;
    ngx_command_t             *cmds;
} ngx_http_aws_auth_conf_ctx_t;


static ngx_str_t  ngx_http_aws_auth_date_var_name =
    ngx_string("aws_auth_date");

static ngx_str_t  ngx_http_aws_auth_host =
    ngx_string("host");

static ngx_str_t  ngx_http_aws_auth_amz_prefix =
    ngx_string("x-amz-");

static ngx_str_t  ngx_http_aws_auth_content_sha_header =
    ngx_string("x-amz-content-sha256");

static ngx_str_t  ngx_http_aws_auth_date_header =
    ngx_string("x-amz-date");

static ngx_str_t  ngx_http_aws_auth_aws4_request =
    ngx_string("aws4_request");

static ngx_str_t  ngx_http_aws_auth_aws4 =
    ngx_string("AWS4");


static ngx_command_t  ngx_http_aws_auth_commands[] = {

    { ngx_string("aws_auth"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_aws_auth_block,
      0,
      0,
      NULL },

    { ngx_string("aws_auth_presign"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_aws_auth_presign,
      0,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_aws_auth_module_ctx = {
    ngx_http_aws_auth_preconfiguration,  /* preconfiguration */
    NULL,                                /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    NULL,                                /* create location configuration */
    NULL                                 /* merge location configuration */
};

ngx_module_t ngx_http_aws_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_aws_auth_module_ctx,       /* module context */
    ngx_http_aws_auth_commands,          /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_command_t  ngx_http_aws_auth_block_commands[] = {

    { ngx_string("access_key"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_http_aws_auth_ctx_t, access_key),
      NULL },

    { ngx_string("secret_key"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_http_aws_auth_ctx_t, secret_key),
      NULL },

    { ngx_string("service"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_http_aws_auth_ctx_t, service),
      NULL },

    { ngx_string("region"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_http_aws_auth_ctx_t, region),
      NULL },

    ngx_null_command
};


static ngx_uint_t  argument_number[] = {
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2,
    NGX_CONF_TAKE3,
    NGX_CONF_TAKE4,
    NGX_CONF_TAKE5,
    NGX_CONF_TAKE6,
    NGX_CONF_TAKE7
};


static void
ngx_http_aws_auth_sha256_hex(ngx_str_t *message, u_char *digest)
{
    u_char      hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX  sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message->data, message->len);
    SHA256_Final(hash, &sha256);

    ngx_hex_dump(digest, hash, sizeof(hash));
}


static ngx_int_t
ngx_http_aws_auth_hmac_sha256(ngx_http_request_t *r, ngx_str_t *key,
    ngx_str_t *message, ngx_str_t *dest)
{
    unsigned   hash_len;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX   hmac_buf;
#endif
    HMAC_CTX  *hmac;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    hmac = HMAC_CTX_new();
    if (hmac == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_hmac_sha256: HMAC_CTX_new failed");
        return NGX_ERROR;
    }
#else
    hmac = &hmac_buf;
    HMAC_CTX_init(hmac);
#endif
    HMAC_Init_ex(hmac, key->data, key->len, EVP_sha256(), NULL);
    HMAC_Update(hmac, message->data, message->len);
    HMAC_Final(hmac, dest->data, &hash_len);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    HMAC_CTX_free(hmac);
#else
    HMAC_CTX_cleanup(hmac);
#endif

    dest->len = hash_len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_aws_auth_hmac_sha256_hex(ngx_http_request_t *r, ngx_str_t *key,
    ngx_str_t *message, ngx_str_t *dest)
{
    u_char     hash_buf[EVP_MAX_MD_SIZE];
    ngx_str_t  hash;

    hash.data = hash_buf;

    if (ngx_http_aws_auth_hmac_sha256(r, key, message, &hash) != NGX_OK) {
        return NGX_ERROR;
    }

    dest->len = ngx_hex_dump(dest->data, hash.data, hash.len) - dest->data;
    return NGX_OK;
}


static ngx_int_t
ngx_http_aws_auth_date_time(ngx_http_request_t *r, ngx_str_t *date)
{
    struct tm  tm;

    date->data = ngx_pnalloc(r->pool, AMZ_DATE_TIME_MAX_LEN);
    if (date->data == NULL) {
        return NGX_ERROR;
    }

    ngx_libc_gmtime(ngx_time(), &tm);
    date->len = strftime((char *) date->data, AMZ_DATE_TIME_MAX_LEN,
        "%Y%m%dT%H%M%SZ", &tm);
    if (date->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_date_time: strftime failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_aws_auth_date_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  date;

    if (ngx_http_aws_auth_date_time(r, &date) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = date.data;
    v->len = date.len;
    v->valid = 1;

    return NGX_OK;
}


static int ngx_libc_cdecl
ngx_http_aws_auth_compare_strs(const void *one, const void *two)
{
    size_t            len;
    ngx_int_t         rc;
    const ngx_str_t  *s1 = one;
    const ngx_str_t  *s2 = two;

    len = ngx_min(s1->len, s2->len);
    rc = ngx_memcmp(s1->data, s2->data, len);
    if (rc != 0) {
        return rc;
    }

    if (s1->len < s2->len) {
        return -1;
    }

    if (s1->len > s2->len) {
        return 1;
    }

    return 0;
}


static int ngx_libc_cdecl
ngx_http_aws_auth_compare_keyvals(const void *one, const void *two)
{
    const ngx_keyval_t  *h1 = one;
    const ngx_keyval_t  *h2 = two;

    return ngx_http_aws_auth_compare_strs(&h1->key, &h2->key);
}


static ngx_int_t
ngx_http_aws_auth_get_signed_headers(ngx_http_request_t *r, ngx_buf_t *request,
    ngx_array_t *headers, ngx_str_t *date, ngx_str_t *content_sha)
{
    ngx_int_t      rc;
    ngx_str_t      key;
    ngx_flag_t     required;
    ngx_keyval_t  *h;

    date->len = 0;
    content_sha->len = 0;

    if (ngx_array_init(headers, r->pool, 5, sizeof(*h)) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_parse_header_line(r, request, 1);

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            break;
        }

        if (rc != NGX_OK) {

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_aws_auth_get_signed_headers: "
                "failed to parse request header %i", rc);
            return NGX_ERROR;
        }

        /* a header line has been parsed successfully */

        key.data = r->header_name_start;
        key.len = r->header_name_end - r->header_name_start;

        required = 0;

        if (key.len == ngx_http_aws_auth_host.len &&
            ngx_strncasecmp(key.data, ngx_http_aws_auth_host.data,
                ngx_http_aws_auth_host.len) == 0)
        {
            required = 1;
        }
        else if (key.len > ngx_http_aws_auth_amz_prefix.len &&
            ngx_strncasecmp(key.data, ngx_http_aws_auth_amz_prefix.data,
                ngx_http_aws_auth_amz_prefix.len) == 0)
        {
            required = 1;
        }

        if (!required) {
            continue;
        }

        h = ngx_array_push(headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->key.data = ngx_pnalloc(r->pool, key.len);
        if (h->key.data == NULL) {
            return NGX_ERROR;
        }

        h->key.len = key.len;

        if (key.len == r->lowcase_index) {
            ngx_memcpy(h->key.data, r->lowcase_header, key.len);

        } else {
            ngx_strlow(h->key.data, key.data, key.len);
        }

        h->value.data = r->header_start;
        h->value.len = r->header_end - r->header_start;

        if (key.len == ngx_http_aws_auth_content_sha_header.len &&
            ngx_strncmp(h->key.data, ngx_http_aws_auth_content_sha_header.data,
                ngx_http_aws_auth_content_sha_header.len) == 0)
        {
            *content_sha = h->value;
        }

        if (key.len == ngx_http_aws_auth_date_header.len &&
            ngx_strncmp(h->key.data, ngx_http_aws_auth_date_header.data,
                ngx_http_aws_auth_date_header.len) == 0)
        {
            *date = h->value;
        }
    }

    return NGX_OK;
}


static uintptr_t
ngx_normalize_uri(u_char *dst, u_char *src, size_t size)
{
    u_char          ch;
    ngx_int_t       num;
    ngx_uint_t      n;
    static u_char   hex[] = "0123456789ABCDEF";

                    /* " ", "#", "%", "?", %00-%1F, %7F-%FF */

                    /* not ALPHA, DIGIT, "-", ".", "_", "~" */

    static uint32_t   escape[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0xfc001fff, /* 1111 1100 0000 0000  0001 1111 1111 1111 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x78000001, /* 0111 1000 0000 0000  0000 0000 0000 0001 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };


    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n = 0;

        while (size) {
            if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
                n++;
            }
            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {

        switch (*src) {

        case '+':
            ch = ' ';
            src++;
            size--;
            break;

        case '%':
            if (size >= 3) {
                num = ngx_hextoi(src + 1, 2);
                if (num != NGX_ERROR) {
                    ch = num;
                    src += 3;
                    size -= 3;
                    break;
                }
            }

            /* fall through */

        default:
            ch = *src++;
            size--;
        }

        if (escape[ch >> 5] & (1U << (ch & 0x1f))) {
            *dst++ = '%';
            *dst++ = hex[ch >> 4];
            *dst++ = hex[ch & 0xf];

        } else {
            *dst++ = ch;
        }
    }

    return (uintptr_t) dst;
}


static ngx_int_t
ngx_http_aws_auth_push_args(ngx_str_t *src, ngx_array_t *dst)
{
    u_char     *start, *end, *p;
    ngx_str_t  *str;

    start = src->data;
    end = start + src->len;

    p = start;
    while (p < end) {

        if (*p != '&') {
            p++;
            continue;
        }

        if (p > start) {
            str = ngx_array_push(dst);
            if (str == NULL) {
                return NGX_ERROR;
            }

            str->data = start;
            str->len = p - start;
        }

        p++;
        start = p;
    }

    if (p > start) {
        str = ngx_array_push(dst);
        if (str == NULL) {
            return NGX_ERROR;
        }

        str->data = start;
        str->len = p - start;
    }

    return NGX_OK;
}

static u_char *
ngx_http_aws_auth_sort_args(u_char *p, ngx_pool_t *pool,
    ngx_str_t *args1, ngx_str_t *args2)
{
    ngx_str_t    *elts;
    ngx_uint_t    i;
    ngx_array_t   arr;

    if (ngx_array_init(&arr, pool, 10, sizeof(ngx_str_t)) != NGX_OK) {
        return NULL;
    }

    if (ngx_http_aws_auth_push_args(args1, &arr) != NGX_OK) {
        return NULL;
    }

    if (ngx_http_aws_auth_push_args(args2, &arr) != NGX_OK) {
        return NULL;
    }

    elts = arr.elts;

    ngx_qsort(elts, arr.nelts, sizeof(elts[0]),
        ngx_http_aws_auth_compare_strs);

    for (i = 0; i < arr.nelts; i++) {
        if (i > 0) {
            *p++ = '&';
        }

        p = ngx_copy(p, elts[i].data, elts[i].len);
    }

    return p;
}


static ngx_int_t
ngx_http_aws_auth_canonical_request(ngx_http_request_t *r,
    ngx_http_aws_auth_ctx_t *ctx, ngx_str_t *signed_headers, ngx_str_t *date,
    ngx_str_t *result)
{
    u_char               *p;
    u_char               *pos;
    size_t                alloc_size;
    uintptr_t             escape;
    ngx_int_t             rc;
    ngx_buf_t            *request;
    ngx_str_t             method;
    ngx_str_t             content_sha;
    ngx_array_t           headers;
    ngx_keyval_t         *h;
    ngx_keyval_t         *last;
    ngx_http_upstream_t  *u;

    /* make ngx_http_proxy generate the request for us */
    u = r->upstream;
    if (u == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: no upstream");
        return NGX_ERROR;
    }

    ctx->ignore = 1;
    rc = r->upstream->create_request(r);
    ctx->ignore = 0;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: create request failed %i",
            rc);
        return NGX_ERROR;
    }

    if (u->request_bufs == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: no request bufs");
        return NGX_ERROR;
    }

    if (u->request_bufs->next != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: more than one request buf");
        return NGX_ERROR;
    }

    request = u->request_bufs->buf;
    u->request_bufs = NULL;

    /* get the method */
    pos = ngx_strlchr(request->pos, request->last, ' ');
    if (pos == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: no space in request buf");
        return NGX_ERROR;
    }
    method.data = request->pos;
    method.len = pos - method.data;

    /* get the uri */
    if (ngx_strlchr(u->uri.data, u->uri.data + u->uri.len, '?') != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: query args not supported");
        return NGX_ERROR;
    }

    /* skip the request line */
    request->pos = ngx_strlchr(request->pos, request->last, LF);
    if (request->pos == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: no LF in request buf");
        return NGX_ERROR;
    }
    request->pos++;

    /* get headers */
    if (ngx_http_aws_auth_get_signed_headers(r, request,
        &headers, date, &content_sha) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!content_sha.len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: no %V header",
            &ngx_http_aws_auth_content_sha_header);
        return NGX_ERROR;
    }

    if (!date->len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: no %V header",
            &ngx_http_aws_auth_date_header);
        return NGX_ERROR;
    }

    ngx_qsort(headers.elts, headers.nelts, sizeof(ngx_keyval_t),
        ngx_http_aws_auth_compare_keyvals);

    last = (ngx_keyval_t *) headers.elts + headers.nelts;

    signed_headers->len = 0;
    alloc_size = 0;

    for (h = headers.elts; h < last; h++) {
        signed_headers->len += h->key.len + 1;
        alloc_size += h->key.len + h->value.len + 2;    /* 2 = : + LF */
    }

    /* build signed headers string */
    if (signed_headers->len > 0) {

        signed_headers->data = ngx_pnalloc(r->pool, signed_headers->len);
        if (signed_headers->data == NULL) {
            return NGX_ERROR;
        }

        p = signed_headers->data;
        for (h = headers.elts; h < last; h++) {
            p = ngx_copy(p, h->key.data, h->key.len);
            *p++ = ';';
        }

        signed_headers->len--;       /* remove the last ; */
    }

    /* canonical request */
    escape = ngx_normalize_uri(NULL, u->uri.data, u->uri.len);

    alloc_size += method.len + u->uri.len + 2 * escape + signed_headers->len +
        content_sha.len + 5;  /* 5 = LFs */

    result->data = ngx_pnalloc(r->pool, alloc_size);
    if (result->data == NULL) {
        return NGX_ERROR;
    }

    p = result->data;
    p = ngx_copy(p, method.data, method.len);
    *p++ = LF;

    p = (u_char *) ngx_normalize_uri(p, u->uri.data, u->uri.len);
    *p++ = LF;

    *p++ = LF;  /* no query params */

    for (h = headers.elts; h < last; h++) {
        p = ngx_copy(p, h->key.data, h->key.len);
        *p++ = ':';
        p = ngx_copy(p, h->value.data, h->value.len);
        *p++ = LF;
    }
    *p++ = LF;
    p = ngx_copy(p, signed_headers->data, signed_headers->len);
    *p++ = LF;
    p = ngx_copy(p, content_sha.data, content_sha.len);

    result->len = p - result->data;

    if (result->len > alloc_size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_aws_auth_canonical_request: "
            "result size %uz greater than allocated size %uz",
            result->len, alloc_size);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_aws_auth_generate_signing_key(ngx_http_request_t *r,
    ngx_http_aws_auth_ctx_t  *ctx)
{
    u_char     *p;
    u_char      date_buf[AMZ_DATE_MAX_LEN];
    struct tm   tm;
    ngx_str_t   date;
    ngx_str_t  *signing_key;

    /* get the GMT date */
    ngx_libc_gmtime(ngx_time(), &tm);
    date.len = strftime((char *) date_buf, sizeof(date_buf), "%Y%m%d", &tm);
    if (date.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_generate_signing_key: strftime failed");
        return NGX_ERROR;
    }
    date.data = date_buf;

    /* check whether date changed since last time */
    if (ctx->signing_key_date.len == date.len &&
        ngx_memcmp(date.data, ctx->signing_key_date.data, date.len) == 0)
    {
        return NGX_OK;
    }

    /* generate a key */
    ctx->signing_key_date.len = 0;

    signing_key = &ctx->signing_key;

    if (ngx_http_aws_auth_hmac_sha256(r, &ctx->secret_key_prefix, &date,
        signing_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_aws_auth_hmac_sha256(r, signing_key, &ctx->region,
        signing_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_aws_auth_hmac_sha256(r, signing_key, &ctx->service,
        signing_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_aws_auth_hmac_sha256(r, signing_key,
        &ngx_http_aws_auth_aws4_request, signing_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* save the date and key scope */
    ctx->signing_key_date.len = date.len;
    ngx_memcpy(ctx->signing_key_date.data, date.data, date.len);

    p = ngx_copy(ctx->key_scope.data, ctx->signing_key_date.data,
        ctx->signing_key_date.len);
    p = ngx_copy(p, ctx->key_scope_suffix.data, ctx->key_scope_suffix.len);
    ctx->key_scope.len = p - ctx->key_scope.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_aws_auth_sign(ngx_http_request_t *r, ngx_http_aws_auth_ctx_t *ctx,
    ngx_str_t *canonical, ngx_str_t *date, ngx_str_t *signature)
{
    u_char     *p;
    size_t      alloc_size;
    ngx_str_t   string_to_sign;
    ngx_str_t   canonical_sha256;

    u_char      canonical_sha256_buf[SHA256_DIGEST_HEX_LENGTH];

    static const char  string_to_sign_template[] =
        "AWS4-HMAC-SHA256\n"
        "%V\n"
        "%V\n"
        "%V";

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_http_aws_auth_sign: date=%V, canonical_request=%V",
        date, canonical);

    ngx_http_aws_auth_sha256_hex(canonical, canonical_sha256_buf);

    canonical_sha256.data = canonical_sha256_buf;
    canonical_sha256.len = sizeof(canonical_sha256_buf);

    alloc_size = sizeof(string_to_sign_template) + date->len
        + ctx->key_scope.len + canonical_sha256.len;

    string_to_sign.data = ngx_pnalloc(r->pool, alloc_size);
    if (string_to_sign.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(string_to_sign.data, string_to_sign_template,
        date, &ctx->key_scope, &canonical_sha256);

    string_to_sign.len = p - string_to_sign.data;

    if (string_to_sign.len > alloc_size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_aws_auth_sign: "
            "result size %uz greater than allocated size %uz",
            string_to_sign.len, alloc_size);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_http_aws_auth_sign: string_to_sign=%V", &string_to_sign);

    return ngx_http_aws_auth_hmac_sha256_hex(r, &ctx->signing_key,
        &string_to_sign, signature);
}

static ngx_int_t
ngx_http_aws_auth_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    u_char                   *p;
    size_t                    alloc_size;
    ngx_str_t                 date;
    ngx_str_t                 result;
    ngx_str_t                 signature;
    ngx_str_t                 signed_headers;
    ngx_str_t                 canonical_request;
    ngx_http_aws_auth_ctx_t  *ctx;

    u_char                    signature_buf[HMAC_DIGEST_MAX_HEX_LENGTH];

    static const char  authorization_template[] =
        "AWS4-HMAC-SHA256 Credential=%V/%V, "
        "SignedHeaders=%V, "
        "Signature=%V";

    ctx = (void *) data;

    if (ctx->ignore) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_http_aws_auth_canonical_request(r, ctx, &signed_headers, &date,
        &canonical_request) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_aws_auth_generate_signing_key(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    signature.data = signature_buf;
    if (ngx_http_aws_auth_sign(r, ctx, &canonical_request, &date, &signature)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    alloc_size = sizeof(authorization_template) + ctx->access_key.len +
        ctx->key_scope.len + signed_headers.len + signature.len;

    result.data = ngx_pnalloc(r->pool, alloc_size);
    if (result.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(result.data, authorization_template, &ctx->access_key,
        &ctx->key_scope, &signed_headers, &signature);

    result.len = p - result.data;

    if (result.len > alloc_size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_aws_auth_variable: "
            "result size %uz greater than allocated size %uz",
            result.len, alloc_size);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_http_aws_auth_variable: result=%V", &result);

    v->data = result.data;
    v->len = result.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_aws_auth_presign_parse_url(ngx_http_request_t *r,
    ngx_http_aws_auth_presign_ctx_t *ctx,
    ngx_http_aws_auth_presign_parse_t *res)
{
    size_t      add;
    u_char     *uri_end;
    u_short     port;
    ngx_str_t   value;
    ngx_url_t   url;

    if (ngx_http_complex_value(r, &ctx->url, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    /* skip the scheme */

    if (value.len > 7
        && ngx_strncasecmp(value.data, (u_char *) "http://", 7) == 0)
    {
        add = 7;
        port = 80;

    } else if (value.len > 8
        && ngx_strncasecmp(value.data, (u_char *) "https://", 8) == 0)
    {
        add = 8;
        port = 443;

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_presign_parse_url: "
            "invalid URL prefix in \"%V\"", &value);
        return NGX_ERROR;
    }

    /* split the host/uri */

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url.len = value.len - add;
    url.url.data = value.data + add;
    url.default_port = port;
    url.uri_part = 1;
    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_aws_auth_presign_parse_url: "
                "%s in aws auth url \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    /* split the uri/args */
    uri_end = url.uri.data + url.uri.len;
    res->uri.data = url.uri.data;
    res->args.data = ngx_strlchr(url.uri.data, uri_end, '?');
    if (res->args.data != NULL) {
        res->uri.len = res->args.data - url.uri.data;
        res->args.data++;
        res->args.len = uri_end - res->args.data;

    } else {
        res->uri.len = url.uri.len;
        res->args.len = 0;
    }

    res->url = value;
    res->host = url.host;

    return NGX_OK;
}


static ngx_int_t
ngx_http_aws_auth_presign_get_args(ngx_http_request_t *r,
    ngx_http_aws_auth_ctx_t *ctx, ngx_str_t *date, ngx_str_t *args)
{
    u_char     *p;
    size_t      alloc_size;
    uintptr_t   access_key_escape;
    uintptr_t   key_scope_escape;

    access_key_escape = ngx_escape_uri(NULL, ctx->access_key.data,
        ctx->access_key.len, NGX_ESCAPE_URI_COMPONENT);

    key_scope_escape = ngx_escape_uri(NULL, ctx->key_scope.data,
        ctx->key_scope.len, NGX_ESCAPE_URI_COMPONENT);

    alloc_size = sizeof(PRESIGN_AMZ_ARGS) - 1
        + ctx->access_key.len + 2 * access_key_escape
        + sizeof(URI_ESCAPE_SLASH) - 1
        + ctx->key_scope.len + 2 * key_scope_escape
        + sizeof(PRESIGN_AMZ_ARG_DATE) - 1
        + date->len;

    p = ngx_pnalloc(r->pool, alloc_size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    args->data = p;

    p = ngx_copy(p, PRESIGN_AMZ_ARGS, sizeof(PRESIGN_AMZ_ARGS) - 1);

    if (access_key_escape) {
        p = (u_char *) ngx_escape_uri(p, ctx->access_key.data,
            ctx->access_key.len, NGX_ESCAPE_URI_COMPONENT);

    } else {
        p = ngx_copy(p, ctx->access_key.data, ctx->access_key.len);
    }

    p = ngx_copy(p, URI_ESCAPE_SLASH, sizeof(URI_ESCAPE_SLASH) - 1);

    p = (u_char *) ngx_escape_uri(p, ctx->key_scope.data, ctx->key_scope.len,
        NGX_ESCAPE_URI_COMPONENT);

    p = ngx_copy(p, PRESIGN_AMZ_ARG_DATE, sizeof(PRESIGN_AMZ_ARG_DATE) - 1);

    p = ngx_copy(p, date->data, date->len);

    args->len = p - args->data;

    if (args->len > alloc_size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_aws_auth_presign_get_args: "
            "result size %uz greater than allocated size %uz",
            args->len, alloc_size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_aws_auth_presign_canonical(ngx_http_request_t *r,
    ngx_http_aws_auth_presign_parse_t *url, ngx_str_t *extra_args,
    ngx_str_t *canonical)
{
    u_char     *p;
    size_t      alloc_size;
    uintptr_t   uri_escape;

    uri_escape = ngx_normalize_uri(NULL, url->uri.data, url->uri.len);

    alloc_size = ngx_http_core_get_method.len + 1
        + url->uri.len + 2 * uri_escape + 1
        + url->args.len + extra_args->len + 2
        + sizeof(PRESIGN_HOST_HEADER) - 1 + url->host.len + 1
        + sizeof(PRESIGN_CANONICAL_SUFFIX) - 1;

    p = ngx_pnalloc(r->pool, alloc_size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    canonical->data = p;

    /* method */
    p = ngx_copy(p, ngx_http_core_get_method.data,
        ngx_http_core_get_method.len);
    *p++ = LF;

    /* uri */
    p = (u_char *) ngx_normalize_uri(p, url->uri.data, url->uri.len);
    *p++ = LF;

    /* args */
    p = ngx_http_aws_auth_sort_args(p, r->pool, &url->args, extra_args);
    if (p == NULL) {
        return NGX_ERROR;
    }
    *p++ = LF;

    /* signed headers + payload */
    p = ngx_copy(p, PRESIGN_HOST_HEADER, sizeof(PRESIGN_HOST_HEADER) - 1);
    p = ngx_copy(p, url->host.data, url->host.len);
    *p++ = LF;

    p = ngx_copy(p, PRESIGN_CANONICAL_SUFFIX,
        sizeof(PRESIGN_CANONICAL_SUFFIX) - 1);

    canonical->len = p - canonical->data;

    if (canonical->len > alloc_size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_aws_auth_presign_canonical: "
            "result size %uz greater than allocated size %uz",
            canonical->len, alloc_size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_aws_auth_presign_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                             *p;
    size_t                              alloc_size;
    ngx_str_t                           date;
    ngx_str_t                           result;
    ngx_str_t                           canonical;
    ngx_str_t                           signature;
    ngx_str_t                           extra_args;
    ngx_http_aws_auth_ctx_t            *ctx;
    ngx_http_aws_auth_presign_ctx_t    *pctx;
    ngx_http_aws_auth_presign_parse_t   url;

    u_char  signature_buf[HMAC_DIGEST_MAX_HEX_LENGTH];

    pctx = (void *) data;
    ctx = pctx->base;

    /* TODO: handle args escaping - escape all chars in keys & values except:
        ALPHA, DIGIT, "-", ".", "_", "~" */

    if (ngx_http_aws_auth_presign_parse_url(r, pctx, &url) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_aws_auth_generate_signing_key(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_aws_auth_date_time(r, &date) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_aws_auth_presign_get_args(r, ctx, &date, &extra_args)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_aws_auth_presign_canonical(r, &url, &extra_args, &canonical)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    signature.data = signature_buf;
    if (ngx_http_aws_auth_sign(r, ctx, &canonical, &date, &signature)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    alloc_size = url.url.len
        + 1 + extra_args.len
        + sizeof(PRESIGN_AMZ_ARG_SIG) - 1 + signature.len;

    p = ngx_pnalloc(r->pool, alloc_size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    result.data = p;

    p = ngx_copy(p, url.url.data, url.url.len);

    *p++ = url.args.len ? '&' : '?';
    p = ngx_copy(p, extra_args.data, extra_args.len);

    p = ngx_copy(p, PRESIGN_AMZ_ARG_SIG, sizeof(PRESIGN_AMZ_ARG_SIG) - 1);
    p = ngx_copy(p, signature.data, signature.len);

    result.len = p - result.data;

    if (result.len > alloc_size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_aws_auth_presign_variable: "
            "result size %uz greater than allocated size %uz",
            result.len, alloc_size);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_http_aws_auth_presign_variable: result=%V", &result);

    v->data = result.data;
    v->len = result.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}


/* copied from ngx_conf_handler, removed support for modules */
static char *
ngx_http_aws_auth_command_handler(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf)
{
    ngx_http_aws_auth_conf_ctx_t  *ctx;
    ngx_command_t                 *cmd;
    ngx_str_t                     *name;
    char                          *rv;

    ctx = cf->ctx;
    cmd = ctx->cmds;

    name = cf->args->elts;

    for ( /* void */; cmd->name.len; cmd++) {

        if (name->len != cmd->name.len) {
            continue;
        }

        if (ngx_strcmp(name->data, cmd->name.data) != 0) {
            continue;
        }

        /* is the directive's argument count right ? */

        if (!(cmd->type & NGX_CONF_ANY)) {

            if (cmd->type & NGX_CONF_FLAG) {

                if (cf->args->nelts != 2) {
                    goto invalid;
                }

            }
            else if (cmd->type & NGX_CONF_1MORE) {

                if (cf->args->nelts < 2) {
                    goto invalid;
                }

            }
            else if (cmd->type & NGX_CONF_2MORE) {

                if (cf->args->nelts < 3) {
                    goto invalid;
                }

            }
            else if (cf->args->nelts > NGX_CONF_MAX_ARGS) {

                goto invalid;

            }
            else if (!(cmd->type & argument_number[cf->args->nelts - 1]))
            {
                goto invalid;
            }
        }

        rv = cmd->set(ctx->cf, cmd, conf);

        if (rv == NGX_CONF_OK) {
            return NGX_CONF_OK;
        }

        if (rv == NGX_CONF_ERROR) {
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"%s\" directive %s", name->data, rv);

        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "unknown directive \"%s\"", name->data);

    return NGX_CONF_ERROR;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "invalid number of arguments in \"%s\" directive",
        name->data);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_aws_auth_init_ctx(ngx_conf_t *cf, ngx_http_aws_auth_ctx_t *ctx)
{
    u_char *p;

    /* add prefix to secret key */
    ctx->secret_key_prefix.data = ngx_pnalloc(cf->pool,
        ngx_http_aws_auth_aws4.len + ctx->secret_key.len);
    if (ctx->secret_key_prefix.data == NULL) {
        return NGX_CONF_ERROR;
    }
    p = ctx->secret_key_prefix.data;
    p = ngx_copy(p, ngx_http_aws_auth_aws4.data, ngx_http_aws_auth_aws4.len);
    p = ngx_copy(p, ctx->secret_key.data, ctx->secret_key.len);
    ctx->secret_key_prefix.len = p - ctx->secret_key_prefix.data;

    /* init key scope suffix */
    ctx->key_scope_suffix.data = ngx_pnalloc(cf->pool, ctx->region.len +
        ctx->service.len + ngx_http_aws_auth_aws4_request.len + 3);
    if (ctx->key_scope_suffix.data == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ctx->key_scope_suffix.data;
    *p++ = '/';
    p = ngx_copy(p, ctx->region.data, ctx->region.len);
    *p++ = '/';
    p = ngx_copy(p, ctx->service.data, ctx->service.len);
    *p++ = '/';
    p = ngx_copy(p, ngx_http_aws_auth_aws4_request.data,
        ngx_http_aws_auth_aws4_request.len);
    ctx->key_scope_suffix.len = p - ctx->key_scope_suffix.data;

    /* alloc additional buffers */
    p = ngx_pnalloc(cf->pool, AMZ_DATE_MAX_LEN + EVP_MAX_MD_SIZE +
        AMZ_DATE_MAX_LEN + ctx->key_scope_suffix.len);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->signing_key_date.data = p;
    p += AMZ_DATE_MAX_LEN;

    ctx->signing_key.data = p;
    p += EVP_MAX_MD_SIZE;

    ctx->key_scope.data = p;

    return NGX_CONF_OK;
}


static ngx_http_aws_auth_ctx_t *
ngx_http_aws_auth_get_ctx(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_hash_key_t             *key;
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {

        if (name->len != key[i].key.len
            || ngx_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (v->get_handler != ngx_http_aws_auth_variable) {
            return NULL;
        }

        return (void *) v->data;
    }

    return NULL;
}


static char *
ngx_http_aws_auth_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_aws_auth_conf_ctx_t   conf_ctx;
    ngx_http_aws_auth_ctx_t       *ctx;
    ngx_http_variable_t           *var;
    ngx_conf_t                     save;
    ngx_str_t                     *value;
    ngx_str_t                      name;
    char                          *rv;

    value = cf->args->elts;

    /* get the variable name */
    name = value[1];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    /* initialize the context */
    ctx = ngx_pcalloc(cf->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    /* add the variable */
    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_aws_auth_variable;
    var->data = (uintptr_t) ctx;

    /* parse the block */
    conf_ctx.cmds = ngx_http_aws_auth_block_commands;
    conf_ctx.cf = &save;

    save = *cf;

    cf->ctx = &conf_ctx;
    cf->handler = ngx_http_aws_auth_command_handler;
    cf->handler_conf = (void *) ctx;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    /* check required params */
    if (ctx->access_key.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "access_key not set in aws_auth block");
        return NGX_CONF_ERROR;
    }

    if (ctx->secret_key.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "secret_key not set in aws_auth block");
        return NGX_CONF_ERROR;
    }

    if (ctx->service.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "service not set in aws_auth block");
        return NGX_CONF_ERROR;
    }

    if (ctx->region.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "region not set in aws_auth block");
        return NGX_CONF_ERROR;
    }

    return ngx_http_aws_auth_init_ctx(cf, ctx);
}


static char *
ngx_http_aws_auth_presign(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                          name;
    ngx_str_t                         *value;
    ngx_http_variable_t               *var;
    ngx_http_aws_auth_presign_ctx_t   *ctx;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ctx = ngx_pcalloc(cf->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    /* get the base ctx */
    name = value[2];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    ctx->base = ngx_http_aws_auth_get_ctx(cf, &name);
    if (ctx->base == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "unknown variable \"$%V\", use a variable "
            "defined using the \"aws_auth\" directive", &name);
        return NGX_CONF_ERROR;
    }

    /* compile the url value */
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = &ctx->url;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* add the variable */
    name = value[1];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_aws_auth_presign_variable;
    var->data = (uintptr_t) ctx;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_aws_auth_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_aws_auth_date_var_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_aws_auth_date_time_variable;

    return NGX_OK;
}
