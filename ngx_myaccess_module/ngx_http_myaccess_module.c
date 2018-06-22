#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <dlfcn.h>
#include <fcntl.h>

//add by tu
#define DATABASE_PATH  "/mnt/hgfs/linux_study/testc++/testc++/test/sqlite_test/test.db"
static ngx_http_request_t  *rs;
static ngx_int_t sig_flag = 0;
static ngx_int_t current_sum_blacklist = 0;
int (*ngx_http_myaccess_open_database)(const char *path);
char** (*ngx_http_myaccess_get_info_from_blacklist)(const char *sql, int *num);
void (*ngx_http_myaccess_get_counts_of_rows_from_blacklist)(int *sum);
void (*ngx_http_myaccess_close_database)();

typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_http_access_rule_t;

#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr   addr;
    struct in6_addr   mask;
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_http_access_rule6_t;

#endif

#if (NGX_HAVE_UNIX_DOMAIN)

typedef struct {
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_http_access_rule_un_t;

#endif

typedef struct {
    ngx_flag_t       enable;     //add by tu
    ngx_array_t      *rules;     /* array of ngx_http_access_rule_t */
#if (NGX_HAVE_INET6)
    ngx_array_t      *rules6;    /* array of ngx_http_access_rule6_t */
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_array_t      *rules_un;  /* array of ngx_http_access_rule_un_t */
#endif
} ngx_http_access_loc_conf_t;

//add by tu
static ngx_http_access_loc_conf_t  *myalcf = NULL;

static ngx_int_t ngx_http_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_access_inet(ngx_http_request_t *r,
    ngx_http_access_loc_conf_t *alcf, in_addr_t addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_http_access_inet6(ngx_http_request_t *r,
    ngx_http_access_loc_conf_t *alcf, u_char *p);
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
static ngx_int_t ngx_http_access_unix(ngx_http_request_t *r,
    ngx_http_access_loc_conf_t *alcf);
#endif
static ngx_int_t ngx_http_access_found(ngx_http_request_t *r, ngx_uint_t deny);
static char *ngx_http_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_access_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_access_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_access_init(ngx_conf_t *cf);

//add by tu
static void ngx_http_myaccess_update_blacklist_values(int sig);
static void ngx_http_myaccess_set_signal_handler_from_myproxy_module(int sig, void (handler)(int));

static ngx_command_t  ngx_http_myaccess_commands[] = {
    /*
    { ngx_string("allowbytu"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_access_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    */

    { ngx_string("mydeny"),
      //NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
      ngx_http_access_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_myaccess_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_access_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_access_create_loc_conf,       /* create location configuration */
    ngx_http_access_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_myaccess_module = {
    NGX_MODULE_V1,
    &ngx_http_myaccess_module_ctx,           /* module context */
    ngx_http_myaccess_commands,              /* module directives */
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


static ngx_int_t
ngx_http_access_handler(ngx_http_request_t *r)
{
    struct sockaddr_in          *sin;
    ngx_http_access_loc_conf_t  *alcf;
#if (NGX_HAVE_INET6)
    u_char                      *p;
    in_addr_t                    addr;
    struct sockaddr_in6         *sin6;
#endif

    //TODO
    rs = r;
    ngx_http_myaccess_set_signal_handler_from_myproxy_module(SIGUSR1, ngx_http_myaccess_update_blacklist_values);
    alcf = myalcf;

    //alcf = ngx_http_get_module_loc_conf(r, ngx_http_myaccess_module);

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        if (alcf->rules) {
            sin = (struct sockaddr_in *) r->connection->sockaddr;
            return ngx_http_access_inet(r, alcf, sin->sin_addr.s_addr);
        }
        break;

#if (NGX_HAVE_INET6)

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        p = sin6->sin6_addr.s6_addr;

        if (alcf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            addr = p[12] << 24;
            addr += p[13] << 16;
            addr += p[14] << 8;
            addr += p[15];
            return ngx_http_access_inet(r, alcf, htonl(addr));
        }

        if (alcf->rules6) {
            return ngx_http_access_inet6(r, alcf, p);
        }

        break;

#endif

#if (NGX_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        if (alcf->rules_un) {
            return ngx_http_access_unix(r, alcf);
        }

        break;

#endif
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_access_inet(ngx_http_request_t *r, ngx_http_access_loc_conf_t *alcf,
    in_addr_t addr)
{
    ngx_uint_t               i;
    ngx_http_access_rule_t  *rule;

    rule = alcf->rules->elts;
    for (i = 0; i < alcf->rules->nelts; i++) {

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %08XD %08XD %08XD",
                       addr, rule[i].mask, rule[i].addr);

        if ((addr & rule[i].mask) == rule[i].addr) {
            return ngx_http_access_found(r, rule[i].deny);
        }
    }

    return NGX_DECLINED;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_http_access_inet6(ngx_http_request_t *r, ngx_http_access_loc_conf_t *alcf,
    u_char *p)
{
    ngx_uint_t                n;
    ngx_uint_t                i;
    ngx_http_access_rule6_t  *rule6;

    rule6 = alcf->rules6->elts;
    for (i = 0; i < alcf->rules6->nelts; i++) {

#if (NGX_DEBUG)
        {
        size_t  cl, ml, al;
        u_char  ct[NGX_INET6_ADDRSTRLEN];
        u_char  mt[NGX_INET6_ADDRSTRLEN];
        u_char  at[NGX_INET6_ADDRSTRLEN];

        cl = ngx_inet6_ntop(p, ct, NGX_INET6_ADDRSTRLEN);
        ml = ngx_inet6_ntop(rule6[i].mask.s6_addr, mt, NGX_INET6_ADDRSTRLEN);
        al = ngx_inet6_ntop(rule6[i].addr.s6_addr, at, NGX_INET6_ADDRSTRLEN);

        ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
        }
#endif

        for (n = 0; n < 16; n++) {
            if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
                goto next;
            }
        }

        return ngx_http_access_found(r, rule6[i].deny);

    next:
        continue;
    }

    return NGX_DECLINED;
}

#endif


#if (NGX_HAVE_UNIX_DOMAIN)

static ngx_int_t
ngx_http_access_unix(ngx_http_request_t *r, ngx_http_access_loc_conf_t *alcf)
{
    ngx_uint_t                  i;
    ngx_http_access_rule_un_t  *rule_un;

    rule_un = alcf->rules_un->elts;
    for (i = 0; i < alcf->rules_un->nelts; i++) {

        /* TODO: check path */
        if (1) {
            return ngx_http_access_found(r, rule_un[i].deny);
        }
    }

    return NGX_DECLINED;
}

#endif


static ngx_int_t
ngx_http_access_found(ngx_http_request_t *r, ngx_uint_t deny)
{
    ngx_http_core_loc_conf_t  *clcf;

    if (deny) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "access forbidden by rule");
        }

        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}

static void ngx_http_myaccess_set_signal_handler_from_myproxy_module(int sig, void (handler)(int))
{
    if (sig_flag == 0) {
        struct sigaction sa;
        ngx_memzero(&sa, sizeof(sa));
        sa.sa_handler = handler;
        sa.sa_flags |= SA_RESTART;
        sigfillset(&sa.sa_mask);
        sigaction(sig, &sa, NULL);
        sig_flag = 1;
    }
}

static void ngx_http_myaccess_update_blacklist_values(int sig)
{
    ngx_int_t                   rc;
    ngx_uint_t                  all;
    ngx_str_t                  *value;
    ngx_cidr_t                  cidr;
    //ngx_http_access_rule_t     *rule;
#if (NGX_HAVE_INET6)
    ngx_http_access_rule6_t    *rule6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_http_access_rule_un_t  *rule_un;
#endif

    ngx_memzero(&cidr, sizeof(ngx_cidr_t));

    //TODO
    myalcf = ngx_http_get_module_loc_conf(rs, ngx_http_myaccess_module);
    void *dp; int flag = 0;int i = 0, sum = 0;
    dp = dlopen("libsqlite_c.so", RTLD_LAZY);
    ngx_http_myaccess_open_database = dlsym(dp, "opendatabase");
    ngx_http_myaccess_get_info_from_blacklist = dlsym(dp, "getinfofromblacklist");
    ngx_http_myaccess_close_database = dlsym(dp, "closedatabase");
    ngx_http_myaccess_get_counts_of_rows_from_blacklist = dlsym(dp, "getnumbersofrowsfromblacklist");
    ngx_http_myaccess_open_database(DATABASE_PATH);
    ngx_http_myaccess_get_counts_of_rows_from_blacklist(&sum);
    value = ngx_palloc(rs->pool, sizeof(ngx_str_t)*sum);
    if (current_sum_blacklist != sum) {

        ngx_array_init(myalcf->rules, rs->pool, sum, sizeof(ngx_http_access_rule_t));
        char **ip_list = ngx_http_myaccess_get_info_from_blacklist("select * from mytable;", &flag);
        while (i <= flag) {
            ngx_str_set(&(value[i]), ip_list[i]);
            value[i].len = ngx_strlen(ip_list[i]);
            all = (value[i].len == 3 && ngx_strcmp(value[i].data, "all") == 0);
            if (!all) {

#if (NGX_HAVE_UNIX_DOMAIN)

                if (value[i].len == 5 && ngx_strcmp(value[i].data, "unix:") == 0) {
                    cidr.family = AF_UNIX;
                    rc = NGX_OK;

                } else {
                    rc = ngx_ptocidr(&value[i], &cidr);

                }

#else
                rc = ngx_ptocidr(&value[i], &cidr);
#endif

                if (rc == NGX_ERROR) {
                    //ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);
                    //return NGX_CONF_ERROR;
                }

                if (rc == NGX_DONE) {
                    //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "low address bits of %V are meaningless", &value[i]);
                }
            }

            if (cidr.family == AF_INET || all) {
                if (myalcf->rules == NULL) {
                    myalcf->rules = ngx_array_create(rs->pool, current_sum_blacklist, sizeof(ngx_http_access_rule_t));
                    if (myalcf->rules == NULL) {
                        //return NGX_CONF_ERROR;
                    }
                }

                ngx_http_access_rule_t *rule = ngx_array_push(myalcf->rules);
                if (rule == NULL) {
                    //return NGX_CONF_ERROR;
                }

                rule->mask = cidr.u.in.mask;
                rule->addr = cidr.u.in.addr;
                rule->deny = 1;
            }

#if (NGX_HAVE_INET6)
            if (cidr.family == AF_INET6 || all) {
                if (myalcf->rules6 == NULL) {
                    myalcf->rules6 = ngx_array_create(rs->pool, 4,
                                                    sizeof(ngx_http_access_rule6_t));
                    if (myalcf->rules6 == NULL) {
                        //return NGX_CONF_ERROR;
                    }
                }

                rule6 = ngx_array_push(myalcf->rules6);
                if (rule6 == NULL) {
                    //return NGX_CONF_ERROR;
                }

                rule6->mask = cidr.u.in6.mask;
                rule6->addr = cidr.u.in6.addr;
                rule6->deny = 1;
            }
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
            if (cidr.family == AF_UNIX || all) {
                if (myalcf->rules_un == NULL) {
                    myalcf->rules_un = ngx_array_create(rs->pool, 1,
                                                    sizeof(ngx_http_access_rule_un_t));
                    if (myalcf->rules_un == NULL) {
                        //return NGX_CONF_ERROR;
                    }
                }

                rule_un = ngx_array_push(myalcf->rules_un);
                if (rule_un == NULL) {
                    //return NGX_CONF_ERROR;
                }
                rule_un->deny = 1;
            }
#endif
            ngx_memzero(&cidr, sizeof(ngx_cidr_t));
            i++;
        }
    }

    current_sum_blacklist = sum;
    ngx_http_myaccess_close_database();
    dlclose(dp);
}

static char *
ngx_http_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_access_loc_conf_t *alcf = conf;

    ngx_int_t                   rc;
    ngx_uint_t                  all;
    ngx_str_t                  *value;
    ngx_cidr_t                  cidr;
    //ngx_http_access_rule_t     *rule;
#if (NGX_HAVE_INET6)
    ngx_http_access_rule6_t    *rule6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_http_access_rule_un_t  *rule_un;
#endif

    ngx_memzero(&cidr, sizeof(ngx_cidr_t));

    //value = ngx_palloc(cf->pool, sizeof(ngx_str_t)*100);
    
    //TODO
    void *dp; int flag = 0;int i = 0, sum = 0;
    dp = dlopen("libsqlite_c.so", RTLD_LAZY);
    ngx_http_myaccess_open_database = dlsym(dp, "opendatabase");
    ngx_http_myaccess_get_info_from_blacklist = dlsym(dp, "getinfofromblacklist");
    ngx_http_myaccess_close_database = dlsym(dp, "closedatabase");
    ngx_http_myaccess_get_counts_of_rows_from_blacklist = dlsym(dp, "getnumbersofrowsfromblacklist");
    ngx_http_myaccess_open_database(DATABASE_PATH);
    ngx_http_myaccess_get_counts_of_rows_from_blacklist(&sum);
    current_sum_blacklist = sum;
    value = ngx_palloc(cf->pool, sizeof(ngx_str_t)*current_sum_blacklist);
    char **ip_list = ngx_http_myaccess_get_info_from_blacklist("select * from mytable;", &flag);
    while (i <= flag) {
        ngx_str_set(&(value[i]), ip_list[i]);
        value[i].len = ngx_strlen(ip_list[i]);
        all = (value[i].len == 3 && ngx_strcmp(value[i].data, "all") == 0);
        if (!all) {

#if (NGX_HAVE_UNIX_DOMAIN)

            if (value[i].len == 5 && ngx_strcmp(value[i].data, "unix:") == 0) {
                cidr.family = AF_UNIX;
                rc = NGX_OK;

            } else {
                rc = ngx_ptocidr(&value[i], &cidr);

            }

#else
            rc = ngx_ptocidr(&value[i], &cidr);
#endif

            if (rc == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "invalid parameter \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (rc == NGX_DONE) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                            "low address bits of %V are meaningless", &value[i]);
            }
        }

        if (cidr.family == AF_INET || all) {

            if (alcf->rules == NULL) {
                alcf->rules = ngx_array_create(cf->pool, current_sum_blacklist, sizeof(ngx_http_access_rule_t));
                if (alcf->rules == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            ngx_http_access_rule_t *rule = ngx_array_push(alcf->rules);
            if (rule == NULL) {
                return NGX_CONF_ERROR;
            }

            rule->mask = cidr.u.in.mask;
            //rule->mask = 0xffffffff;
            rule->addr = cidr.u.in.addr;
            rule->deny = 1;
            //rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "black list ip:%V", &(value[i]));
        }

#if (NGX_HAVE_INET6)
        if (cidr.family == AF_INET6 || all) {

            if (alcf->rules6 == NULL) {
                alcf->rules6 = ngx_array_create(cf->pool, 4,
                                                sizeof(ngx_http_access_rule6_t));
                if (alcf->rules6 == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            rule6 = ngx_array_push(alcf->rules6);
            if (rule6 == NULL) {
                return NGX_CONF_ERROR;
            }

            rule6->mask = cidr.u.in6.mask;
            rule6->addr = cidr.u.in6.addr;
            rule6->deny = 1;
            //rule6->deny = (value[0].data[0] == 'd') ? 1 : 0;
        }
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
        if (cidr.family == AF_UNIX || all) {

            if (alcf->rules_un == NULL) {
                alcf->rules_un = ngx_array_create(cf->pool, 1,
                                                sizeof(ngx_http_access_rule_un_t));
                if (alcf->rules_un == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            rule_un = ngx_array_push(alcf->rules_un);
            if (rule_un == NULL) {
                return NGX_CONF_ERROR;
            }
            rule_un->deny = 1;
            //rule_un->deny = (value[0].data[0] == 'd') ? 1 : 0;
        }
#endif
        ngx_memzero(&cidr, sizeof(ngx_cidr_t));
        i++;
    }
    ngx_http_myaccess_close_database();
    dlclose(dp);

    myalcf = alcf;
    return NGX_CONF_OK;
}

static void *
ngx_http_access_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_access_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_access_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_access_loc_conf_t  *prev = parent;
    ngx_http_access_loc_conf_t  *conf = child;

    if (conf->rules == NULL
#if (NGX_HAVE_INET6)
        && conf->rules6 == NULL
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        && conf->rules_un == NULL
#endif
    ) {
        conf->rules = prev->rules;
#if (NGX_HAVE_INET6)
        conf->rules6 = prev->rules6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        conf->rules_un = prev->rules_un;
#endif
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_access_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_access_handler;

    return NGX_OK;
}
