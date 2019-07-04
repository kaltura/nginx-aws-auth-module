#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/sha.h>


#define SHA256_DIGEST_HEX_LENGTH (SHA256_DIGEST_LENGTH * 2)
#define HMAC_DIGEST_MAX_HEX_LENGTH (EVP_MAX_MD_SIZE * 2)

#define AMZ_DATE_MAX_LEN (sizeof("YYYYmmddTHHMMSSZ"))


static char *ngx_conf_set_base64_str_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_aws_auth_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_aws_auth_preconfiguration(ngx_conf_t *cf);


typedef struct {
    ngx_str_t  access_key;
    ngx_str_t  signing_key;
    ngx_str_t  key_scope;
    unsigned   ignore:1;
} ngx_http_aws_auth_ctx_t;


typedef struct {
    ngx_conf_t *cf;
    ngx_command_t *cmds;
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


static ngx_command_t  ngx_http_aws_auth_commands[] = {

    { ngx_string("aws_auth"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_aws_auth_block,
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

    { ngx_string("signing_key"),
      NGX_CONF_TAKE1,
      ngx_conf_set_base64_str_slot,
      0,
      offsetof(ngx_http_aws_auth_ctx_t, signing_key),
      NULL },

    { ngx_string("key_scope"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_http_aws_auth_ctx_t, key_scope),
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


static char *
ngx_conf_set_base64_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t        *field, *value;
    ngx_conf_post_t  *post;

    field = (ngx_str_t *)(p + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    field->data = ngx_palloc(cf->pool,
        ngx_base64_decoded_length(value[1].len));
    if (field->data == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_decode_base64(field, &value[1]) != NGX_OK) {
        return "is not valid base64";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}


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
ngx_http_aws_auth_hmac_sha256_hex(ngx_http_request_t *r, ngx_str_t *key,
    ngx_str_t *message, ngx_str_t *dest)
{
    u_char     hash[EVP_MAX_MD_SIZE];
    unsigned   hash_len;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX   hmac_buf;
#endif
    HMAC_CTX  *hmac;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    hmac = HMAC_CTX_new();
    if (hmac == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_hmac_sha256_hex: HMAC_CTX_new failed");
        return NGX_ERROR;
    }
#else
    hmac = &hmac_buf;
    HMAC_CTX_init(hmac);
#endif
    HMAC_Init_ex(hmac, key->data, key->len, EVP_sha256(), NULL);
    HMAC_Update(hmac, message->data, message->len);
    HMAC_Final(hmac, hash, &hash_len);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    HMAC_CTX_free(hmac);
#else
    HMAC_CTX_cleanup(hmac);
#endif

    dest->len = ngx_hex_dump(dest->data, hash, hash_len) - dest->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_aws_auth_date(
    ngx_http_request_t *r,
    ngx_http_variable_value_t *v,
    uintptr_t data)
{
    struct tm  tm;

    v->data = ngx_pnalloc(r->pool, AMZ_DATE_MAX_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_libc_gmtime(ngx_time(), &tm);
    v->len = strftime((char*)v->data, AMZ_DATE_MAX_LEN, "%Y%m%dT%H%M%SZ", &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_aws_auth_date: strftime failed");
        return NGX_ERROR;
    }

    v->valid = 1;
    return NGX_OK;
}


static int ngx_libc_cdecl
ngx_http_aws_auth_compare_keyvals(const void *one, const void *two)
{
    const ngx_keyval_t  *h1 = one;
    const ngx_keyval_t  *h2 = two;
    size_t               len = ngx_min(h1->key.len, h2->key.len);
    ngx_int_t            rc;

    rc = ngx_memcmp(h1->key.data, h2->key.data, len);
    if (rc != 0) {
        return rc;
    }

    if (h1->key.len < h2->key.len) {
        return -1;
    }

    if (h1->key.len > h2->key.len) {
        return 1;
    }

    return 0;
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

    ngx_array_init(headers, r->pool, 5, sizeof(*h));

    for (;;) {
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

        h->key.data = ngx_pnalloc(r->pool, key.len);
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

ngx_int_t
ngx_http_aws_auth_canonical_request(ngx_http_request_t *r,
    ngx_http_aws_auth_ctx_t *ctx, ngx_str_t *signed_headers, ngx_str_t *date,
    ngx_str_t *result)
{
    u_char               *p;
    u_char               *pos;
    size_t                alloc_size;
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

    last = (ngx_keyval_t*)headers.elts + headers.nelts;

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
    alloc_size += method.len + u->uri.len + signed_headers->len +
        content_sha.len + 5;  /* 5 = LFs */

    result->data = ngx_pnalloc(r->pool, alloc_size);
    if (result->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(p, method.data, method.len);
    *p++ = LF;
    p = ngx_copy(p, u->uri.data, u->uri.len);
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

    return NGX_OK;
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
    ngx_str_t                 string_to_sign;
    ngx_str_t                 signed_headers;
    ngx_str_t                 canonical_sha256;
    ngx_str_t                 canonical_request;
    ngx_http_aws_auth_ctx_t  *ctx;

    u_char                    signature_buf[HMAC_DIGEST_MAX_HEX_LENGTH];
    u_char                    canonical_sha256_buf[SHA256_DIGEST_HEX_LENGTH];

    static const char string_to_sign_template[] =
        "AWS4-HMAC-SHA256\n"
        "%V\n"
        "%V\n"
        "%V";

    static const char authorization_template[] =
        "AWS4-HMAC-SHA256 Credential=%V/%V, "
        "SignedHeaders=%V, "
        "Signature=%V";

    ctx = (void*)data;

    if (ctx->ignore) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* canonical request */
    if (ngx_http_aws_auth_canonical_request(r, ctx, &signed_headers, &date,
        &canonical_request) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_http_aws_auth_variable: "
        "signed_headers=%V, date=%V, canonical_request=%V",
        &signed_headers, &date, &canonical_request);

    ngx_http_aws_auth_sha256_hex(&canonical_request, canonical_sha256_buf);

    canonical_sha256.data = canonical_sha256_buf;
    canonical_sha256.len = sizeof(canonical_sha256_buf);

    /* string to sign */
    string_to_sign.data = ngx_pnalloc(r->pool,
        sizeof(string_to_sign_template) + date.len + ctx->key_scope.len +
        canonical_sha256.len);
    if (string_to_sign.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(string_to_sign.data, string_to_sign_template,
        &date, &ctx->key_scope, &canonical_sha256);

    string_to_sign.len = p - string_to_sign.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_http_aws_auth_variable: string_to_sign=%V", &string_to_sign);

    /* signature */
    signature.data = signature_buf;

    if (ngx_http_aws_auth_hmac_sha256_hex(r, &ctx->signing_key,
        &string_to_sign, &signature) != NGX_OK) {
        return NGX_ERROR;
    }

    /* result */
    alloc_size = sizeof(authorization_template) + ctx->access_key.len +
        ctx->key_scope.len + signed_headers.len + signature.len;

    result.data = ngx_pnalloc(r->pool, alloc_size);
    if (result.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(result.data, authorization_template, &ctx->access_key,
        &ctx->key_scope, &signed_headers, &signature);

    result.len = p - result.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "ngx_http_aws_auth_variable: result=%V", &result);

    v->data = result.data;
    v->len = result.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

/* copied from ngx_conf_handler, removed support for modules */
static char *
ngx_http_secure_token_command_handler(ngx_conf_t *cf, ngx_command_t *dummy,
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
    var = ngx_http_add_variable(cf, &name, 0);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    /* parse the block */
    var->get_handler = ngx_http_aws_auth_variable;
    var->data = (uintptr_t)ctx;

    conf_ctx.cmds = ngx_http_aws_auth_block_commands;
    conf_ctx.cf = &save;

    save = *cf;

    cf->ctx = &conf_ctx;
    cf->handler = ngx_http_secure_token_command_handler;
    cf->handler_conf = ctx;

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

    if (ctx->signing_key.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "signing_key not set in aws_auth block");
        return NGX_CONF_ERROR;
    }

    if (ctx->key_scope.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "key_scope not set in aws_auth block");
        return NGX_CONF_ERROR;
    }

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

    var->get_handler = ngx_http_aws_auth_date;

    return NGX_OK;
}
