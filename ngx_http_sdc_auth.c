#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static const EVP_MD *evp_md = NULL;

#define SDC_AUTHORIAZTION_VARIABLE "sdc_authorization"
#define SDC_DATE_VARIABLE "sdc_date"

static void* ngx_http_sdc_auth_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_sdc_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t register_variables(ngx_conf_t *cf);

typedef struct {
    ngx_str_t key_path;
    ngx_str_t key_id;
    ngx_str_t user;
    EVP_PKEY *pkey;
} ngx_http_sdc_auth_conf_t;

static ngx_command_t  ngx_http_sdc_auth_commands[] = {
    { ngx_string("sdc_key_path"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sdc_auth_conf_t, key_path),
      NULL },

    { ngx_string("sdc_key_id"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sdc_auth_conf_t, key_id),
      NULL },

    { ngx_string("sdc_user"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sdc_auth_conf_t, user),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_sdc_auth_module_ctx = {
    register_variables,                    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sdc_auth_create_loc_conf,     /* create location configuration */
    ngx_http_sdc_auth_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_sdc_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_sdc_auth_module_ctx,         /* module context */
    ngx_http_sdc_auth_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_sdc_auth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sdc_auth_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sdc_auth_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *
ngx_http_sdc_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sdc_auth_conf_t *prev = parent;
    ngx_http_sdc_auth_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->key_path, prev->key_path, "");
    ngx_conf_merge_str_value(conf->key_id, prev->key_id, "");
    ngx_conf_merge_str_value(conf->user, prev->user, "");

    if (conf->key_path.len != 0) {
        u_char path[conf->key_path.len + 1];
        ngx_sprintf(path, "%V%Z", &conf->key_path);

        FILE *fp = fopen((const char *) path, "r");
        if (fp == NULL) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "Key file not found: %V", &conf->key_path);
            return NGX_CONF_ERROR;
        }
        conf->pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        if (conf->pkey == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

#define MAX_LEN_TO_SIGN 100
#define MAX_LEN_SIGNATURE 400
#define MAX_LEN_AUTHORIZATION 600

static ngx_int_t
ngx_http_sdc_auth_variable_authorization(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_sdc_auth_conf_t *sdc_conf = ngx_http_get_module_loc_conf(r, ngx_http_sdc_auth_module);

    u_char *to_sign = ngx_palloc(r->pool, MAX_LEN_TO_SIGN);
    ngx_snprintf(to_sign, MAX_LEN_TO_SIGN, "date: %V%Z", &ngx_cached_http_time);

    u_char md_value[MAX_LEN_SIGNATURE];
    size_t md_len = MAX_LEN_SIGNATURE;

    if (evp_md == NULL) {
        OpenSSL_add_all_digests();
        evp_md = EVP_get_digestbyname("SHA256");
    }

    ngx_log_debug1(NGX_LOG_DEBUG, r->connection->log, 0, "to_sign: \"%s\"", to_sign);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, evp_md, NULL);
    EVP_DigestSignInit(mdctx, NULL, evp_md, NULL, sdc_conf->pkey);
    EVP_DigestSignUpdate(mdctx, to_sign, ngx_strlen(to_sign));
    EVP_DigestSignFinal(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, md_value, md_len);
    (void)BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    u_char *signature = ngx_palloc(r->pool, bptr->length + 1);
    ngx_memcpy(signature, bptr->data, bptr->length);
    signature[bptr->length] = '\0';

    BIO_free_all(b64);

    int key_type = EVP_PKEY_type(sdc_conf->pkey->type);
    const char *algo = key_type == EVP_PKEY_RSA ? "rsa-sha256" :
        key_type == EVP_PKEY_DSA ? "dsa-sha256" :
        NULL;

    u_char *authorization = ngx_palloc(r->pool, MAX_LEN_AUTHORIZATION);
    ngx_snprintf(authorization, MAX_LEN_AUTHORIZATION, "Signature keyId=\"/%V/keys/%V\",algorithm=\"%s\",signature=\"%s\"%Z", &sdc_conf->user, &sdc_conf->key_id, algo, signature);

    ngx_log_debug2(NGX_LOG_DEBUG, r->connection->log, 0, "Authorization: %s %d", authorization, ngx_strlen(authorization));

    v->len = ngx_strlen(authorization);
    v->data = authorization;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_sdc_auth_variable_date(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    v->len = ngx_cached_http_time.len;
    v->data = ngx_cached_http_time.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_http_variable_t  ngx_http_sdc_auth_vars[] = {
    { ngx_string(SDC_AUTHORIAZTION_VARIABLE), NULL,
      ngx_http_sdc_auth_variable_authorization, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string(SDC_DATE_VARIABLE), NULL,
      ngx_http_sdc_auth_variable_date, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t
register_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_sdc_auth_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

/*
 * vim: ts=4 sw=4 et
 */
