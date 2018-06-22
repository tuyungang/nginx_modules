#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
typedef struct
{
    ngx_str_t subrequest_string;
}ngx_http_mysubrequest_loc_conf_t;
*/

typedef struct
{
    //ngx_str_t *req;
    //ngx_str_t req;
    ngx_buf_t *req;
    //ngx_str_t stock[6];
}ngx_http_mysubrequest_ctx_t;

static ngx_int_t mysubrequest_subrequest_post_handler(ngx_http_request_t *r,void *data,ngx_int_t rc);
static void mysubrequest_post_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mysubrequest_handler(ngx_http_request_t *r);
static char *ngx_http_mysubrequest_string(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
//static void *ngx_http_mysubrequest_create_loc_conf(ngx_conf_t *cf);

static ngx_command_t ngx_http_mysubrequest_commands[] = {
    {
        ngx_string("mysubrequest"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
        ngx_http_mysubrequest_string,
        NGX_HTTP_LOC_CONF_OFFSET,
        0/*offsetof(ngx_http_mysubrequest_loc_conf_t,subrequest_string)*/,
        NULL
    },

    ngx_null_command
};


static ngx_http_module_t ngx_http_mysubrequest_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL/*ngx_http_mysubrequest_create_loc_conf*/,
    NULL
};

ngx_module_t ngx_http_mysubrequest_module = {
    NGX_MODULE_V1,
    &ngx_http_mysubrequest_module_ctx,
    ngx_http_mysubrequest_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

/*
static void *ngx_http_mysubrequest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mysubrequest_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool,sizeof(ngx_http_mysubrequest_loc_conf_t));
    if(conf == NULL)
        return NULL;
    conf->subrequest_string.len = 0;
    conf->subrequest_string.data = NULL;
    return conf;
}
*/

static char *ngx_http_mysubrequest_string(ngx_conf_t *cf, ngx_command_t *cmd,void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
    clcf->handler = ngx_http_mysubrequest_handler;
    //ngx_conf_set_str_slot(cf,cmd,conf);
    return NGX_CONF_OK;
}

static ngx_int_t mysubrequest_subrequest_post_handler(ngx_http_request_t *r,void *data,ngx_int_t rc)
{
    ngx_http_request_t *pr = r->parent;
    ngx_http_mysubrequest_ctx_t *myctx = ngx_http_get_module_ctx(pr,ngx_http_mysubrequest_module);
    if(myctx == NULL){
        return NGX_ERROR;
    }
    pr->headers_out.status = r->headers_out.status;
    //pr->headers_out.location = r->headers_out.location;
    //ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, (const char*)(pr->headers_out.location)->value.data);
    if(r->headers_out.status == NGX_HTTP_OK){
        //ngx_buf_t *pRecvBuf = &r->upstream->buffer;
        myctx->req = &r->upstream->buffer;
        /*
        int flag = 0;
        ngx_buf_t *pRecvBuf = &r->upstream->buffer;
        for(;pRecvBuf->pos!=pRecvBuf->last;pRecvBuf->pos++)
        {
            if(*pRecvBuf->pos==',' || *pRecvBuf->pos == '\"'){
                if(flag>0){
                    myctx->stock[flag-1].len = pRecvBuf->pos-myctx->stock[flag-1].data;
                }
                flag++;
                myctx->stock[flag-1].data = pRecvBuf->pos+1;
            }
            if(flag>6)
                break;
        }
        */
        //ngx_memcpy(myctx->req.data,pRecvBuf->pos,ngx_buf_size(pRecvBuf));
        //myctx->req.len = ngx_buf_size(pRecvBuf);
    }
    pr->write_event_handler = mysubrequest_post_handler;
    //pr->write_event_handler = NULL;
    return NGX_OK;
}

static void mysubrequest_post_handler(ngx_http_request_t *r)
{
    if(r->headers_out.status!=NGX_HTTP_OK){
        ngx_http_finalize_request(r,r->headers_out.status);
        return;
    }
    ngx_http_mysubrequest_ctx_t *myctx = ngx_http_get_module_ctx(r,ngx_http_mysubrequest_module);

    /*
    ngx_str_t output_format = ngx_string("stock[%V],Today current price: %V, volumn: %V");
    int bodylen = output_format.len + myctx->stock[0].len+myctx->stock[1].len+myctx->stock[4].len-6;
    r->headers_out.content_length_n = bodylen;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool,bodylen);
    ngx_snprintf(b->pos,bodylen,(char*)output_format.data,&myctx->stock[0],&myctx->stock[1],&myctx->stock[4]);
    b->last = b->pos + bodylen;
    b->last_buf = 1;
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
    static ngx_str_t type = ngx_string("text/plain; charset=GBK");
    r->headers_out.content_type = type;
    */

    //size_t bodylen = ngx_buf_size(myctx->req);
    myctx->req->last_buf = 1;
    ngx_chain_t out;
    out.buf = myctx->req;
    out.next = NULL;
    /*
    ngx_buf_t *b = ngx_create_temp_buf(r->pool,bodylen);
    b = myctx->req;
    b->last_buf = 1;
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
    */

    r->headers_out.status = NGX_HTTP_OK;
    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r,&out);
    ngx_http_finalize_request(r,ret);
}

static ngx_int_t ngx_http_mysubrequest_handler(ngx_http_request_t *r)
{
    ngx_http_mysubrequest_ctx_t *myctx = ngx_http_get_module_ctx(r,ngx_http_mysubrequest_module);
    if(myctx == NULL){
        myctx = ngx_palloc(r->pool,sizeof(ngx_http_mysubrequest_ctx_t));
        if(myctx == NULL){
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r,myctx,ngx_http_mysubrequest_module);
    }
    ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool,sizeof(ngx_http_mysubrequest_ctx_t));
    if(psr == NULL){
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    psr->handler = mysubrequest_subrequest_post_handler;
    psr->data = myctx;
    //ngx_str_t sub_prefix = ngx_string("/list=");
    ngx_str_t sub_prefix = ngx_string("/password/accounts/login");
    ngx_str_t sub_location;
    //sub_location.len = sub_prefix.len + r->args.len;
    sub_location.len = sub_prefix.len;
    sub_location.data = ngx_palloc(r->pool,sub_location.len);
    //ngx_snprintf(sub_location.data,sub_location.len,"%V%V",&sub_prefix,&r->args);
    ngx_snprintf(sub_location.data,sub_location.len,"%V",&sub_prefix);

    ngx_http_request_t *sr;
    ngx_int_t rc = ngx_http_subrequest(r,&sub_location,NULL,&sr,psr,NGX_HTTP_SUBREQUEST_IN_MEMORY);
    //ngx_int_t rc = ngx_http_subrequest(r,&sub_location,NULL,&sr,psr,0);
    if(rc != NGX_OK){
        return NGX_ERROR;
    }
    return NGX_DONE;
}
