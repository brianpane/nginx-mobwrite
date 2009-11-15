/* A module for nginx that proxies requests to the Mobwrite daemon
 *
 * Copyright 2009 Brian Pane
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ngx_config.h>
#include <ngx_http.h>

#include <stdio.h>
#include <stdlib.h>

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

ngx_module_t ngx_http_mobwrite_module;

/* Per-location module configuration */
typedef struct {
  ngx_http_upstream_conf_t upstream;
} ngx_http_mobwrite_loc_conf_t;

/* Output formats for Mobwrite */
typedef enum { MOBWRITE_FMT_UNSET, MOBWRITE_FMT_TXT, MOBWRITE_FMT_JS } mobwrite_format_t;

/* Per-request state */
typedef struct {
  mobwrite_format_t format;  /* output format requested by the client */
  int response_started; /* true if we have sent any of the respone body */
} ngx_http_mobwrite_ctx_t;

/* Print out the contents of a buffer chain for debugging */
void
dump_buffer_chain(ngx_chain_t *chain)
{
  int counter = 0;
  fprintf(stderr, "buffer chain contents: {\n");
  while (chain != NULL) {
    ngx_buf_t *buf;
    const u_char *next_char;
    counter++;
    fprintf(stderr, "    %d: {\n", counter);
    buf = chain->buf;
    fprintf(stderr, "        last: %s\n", (buf->last_buf ? "TRUE" : "FALSE"));
    fprintf(stderr, "        flush: %s\n", (buf->flush ? "TRUE" : "FALSE"));
    fprintf(stderr, "        length: %ld\n", (long)(buf->last - buf->pos));
    fprintf(stderr, "        content: '");
    for (next_char = buf->pos; next_char < buf->last; next_char++) {
      fprintf(stderr, "%c", *((char*)next_char));
    }
    fprintf(stderr, "'\n");
    fprintf(stderr, "    }\n");
    chain = chain->next;
  }
  fprintf(stderr, "}\n");
}

/* Initialize the per-location config structure */
static void *
ngx_http_mobwrite_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_mobwrite_loc_conf_t *mobwrite_conf;
  ngx_http_upstream_conf_t *upstream;
  mobwrite_conf = (ngx_http_mobwrite_loc_conf_t *)ngx_pcalloc(cf->pool, sizeof(*mobwrite_conf));
  upstream = &(mobwrite_conf->upstream);

  upstream->connect_timeout = NGX_CONF_UNSET_MSEC;
  upstream->send_timeout = NGX_CONF_UNSET_MSEC;
  upstream->read_timeout = NGX_CONF_UNSET_MSEC;
  upstream->timeout = NGX_CONF_UNSET_MSEC;

  upstream->send_lowat = 0;
  upstream->buffer_size = NGX_CONF_UNSET_SIZE;

  upstream->busy_buffers_size = 0;
  upstream->max_temp_file_size = 0;
  upstream->temp_file_write_size_conf = 0;

  upstream->bufs.num = 0;

  upstream->ignore_headers = 1;
  upstream->next_upstream = 0;
  upstream->store_access = 0;
  upstream->buffering = 0;
  upstream->pass_request_headers = 0;
  upstream->pass_request_body = 1;
    
  upstream->ignore_client_abort = 0;
  upstream->intercept_errors = 1;
  upstream->cyclic_temp_file = 0;
  
  upstream->temp_path = NULL;

  upstream->hide_headers = NULL;  
  upstream->pass_headers = NULL;

  upstream->store_lengths = NULL;
  upstream->store_values = NULL;

  return mobwrite_conf;
}

static char *
ngx_http_mobwrite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_mobwrite_loc_conf_t *conf = (ngx_http_mobwrite_loc_conf_t *)child;
  ngx_http_mobwrite_loc_conf_t *p_conf = (ngx_http_mobwrite_loc_conf_t *)parent;
  ngx_http_upstream_conf_t *upstream = &(conf->upstream);
  ngx_http_upstream_conf_t *p_upstream = &(p_conf->upstream);

  ngx_conf_merge_msec_value(upstream->connect_timeout, p_upstream->connect_timeout, 5000);
  ngx_conf_merge_msec_value(upstream->send_timeout, p_upstream->send_timeout, 5000);
  ngx_conf_merge_msec_value(upstream->read_timeout, p_upstream->read_timeout, 5000);
  ngx_conf_merge_msec_value(upstream->timeout, p_upstream->timeout, 5000);

  ngx_conf_merge_size_value(upstream->buffer_size, p_upstream->buffer_size, ngx_pagesize);
  
  if (upstream->upstream == NULL) {
    upstream->upstream = p_upstream->upstream;
  }

  return NGX_CONF_OK;
}

/* Given a chain of buffers, concatenate the contents into a single string */
static ngx_str_t
concatenate_text(ngx_pool_t *pool, ngx_chain_t *chain)
{
  ngx_str_t concatenation = ngx_null_string;
  size_t length = 0;
  ngx_chain_t *next = chain;
  int num_bufs = 0;

  /* Iterate through once to find the total length */
  while (next != NULL) {
    ngx_buf_t *buf = chain->buf;
    num_bufs++;
    if (buf != NULL) {
      length += (buf->last - buf->pos);
    }
    next = next->next;
  }

  /* Iterate through a second time to copy the data */
  if (length != 0) {
    concatenation.len = length;
    if (num_bufs == 1) {
      /* Common-case optimization: if just one buffer, skip the copy */
      concatenation.data = chain->buf->pos;
    }
    else {
      /* If more than one buffer, copy into a newly allocated string */
      u_char *data = (u_char *)ngx_palloc(pool, length);
      concatenation.data = data;
      next = chain;
      while (next != NULL) {
        size_t buf_length = next->buf->last - next->buf->pos;
        memcpy(data, next->buf->pos, buf_length);
        data += buf_length;
      }
    }
  }
  return concatenation;
}

/* Find the value of the URL parameter with the specified name */
static ngx_int_t
find_arg(ngx_pool_t *pool, ngx_str_t name, ngx_str_t args, ngx_str_t *value)
{
  u_char *start = args.data;
  u_char *end = start + args.len;
  size_t name_len = name.len;
  while (start < end) {
    if (start + name_len + 1 < end) { /* if enough room for "name=" */
      if ((ngx_strncmp(name.data, start, name_len) == 0) && (start[name_len] == (u_char)'=')) {
        u_char *arg_end;
        u_char *unescaped;
        start += (name_len + 1);  /* skip past the "name=" */
        arg_end = ngx_strlchr(start, end, (u_char)'&'); /* find terminating '&' */
        if (arg_end == NULL) {
          arg_end = end;
        }
        unescaped = (u_char *)ngx_palloc(pool, arg_end - start);
        value->data = unescaped;
        ngx_unescape_uri(&unescaped, &start, arg_end - start, NGX_UNESCAPE_URI);
        value->len = unescaped - value->data;
        return NGX_OK;
      }
    }
    start = ngx_strlchr(start, end, (u_char)'&');
    if (start == NULL) {
      break;
    }
    start++;
  }
  value->data = NULL;
  value->len = 0;
  return NGX_DECLINED;
}

/* Pack a string into a buffer chain that can be processed
   by nginx's asynchronous network I/O engine */
static ngx_chain_t *
str_to_buffer_chain(ngx_str_t str, ngx_pool_t *pool)
{
  ngx_chain_t *chain;
  ngx_buf_t *buf;

  chain = (ngx_chain_t *)ngx_palloc(pool, sizeof(*chain));
  if (chain == NULL) {
    return NULL;
  }
  buf = (ngx_buf_t *)ngx_pcalloc(pool, sizeof(*buf));
  if (buf == NULL) {
    return NULL;
  }
  buf->pos = str.data;
  buf->last = buf->pos + str.len;
  buf->memory = 1;
  chain->buf = buf;
  chain->next = NULL;
  return chain;
}

/* Replace the character at the specified position in a
   chain link's buffer with some text, splitting the buffer
   and updating pointers as needed */
static void
buf_replace(ngx_chain_t *link, u_char *split_at, const char *text, ngx_pool_t *pool)
{
  ngx_str_t str;
  ngx_chain_t *new_link, *remainder_link;

  /* Split the buffer at the specified position, discarding
     the character at that position */
  if (split_at + 1 >= link->buf->last) {
    remainder_link = NULL;
  }
  else {
    remainder_link = (ngx_chain_t *)ngx_palloc(pool, sizeof(ngx_chain_t));
    remainder_link->buf = (ngx_buf_t *)ngx_pcalloc(pool, sizeof(ngx_buf_t));
    *(remainder_link->buf) = *(link->buf);
    remainder_link->buf->pos = split_at + 1;
    if  (link->buf->last_buf) {
      remainder_link->buf->last_buf = 1;
      link->buf->last_buf = 0;
    }
    remainder_link->next = link->next;
  }
  link->buf->last = split_at;

  /* Create a new buffer containing the replacement text, and
     link it in at the point of the split */
  str.len = strlen(text);
  str.data = (u_char *)text;
  new_link = str_to_buffer_chain(str, pool);
  new_link->next = remainder_link;
  link->next = new_link;

  /* This case can happen only when the split is at the
     very end of the last buffer: */
  if (link->buf->last_buf) {
    new_link->buf->last_buf = 1;
    link->buf->last_buf = 0;
  }
}

/* Escape the characters in a chain for inclusion within a Javascript string */
static void
js_escape(ngx_chain_t *chain, ngx_pool_t *pool) {
  ngx_chain_t *current = chain;
  while (current != NULL) {
    int modified = 0;
    u_char *next_char = current->buf->pos;
    while (!modified && (next_char < current->buf->last)) {
      char ch = *((const char*)next_char);
      switch (ch) {
        case '\\':
          buf_replace(current, next_char, "\\\\", pool);
          modified = 1;
          break;
        case '"':
          buf_replace(current, next_char, "\\\"", pool);
          modified = 1;
          break;
        case '\n':
          buf_replace(current, next_char, "\\n", pool);
          modified = 1;
          break;
        case '\r':
          buf_replace(current, next_char, "\\r", pool);
          modified = 1;
          break;
        default:
          next_char++;
      }
    }
    if (modified) {
      /* Skip over the new bucket that we just inserted, since it's already escaped */
      current = current->next->next;
    }
    else {
      current = current->next;
    }
  }
}

/* Callback to create a request to the Mobwrite daemon */
static ngx_int_t
ngx_http_mobwrite_create_request(ngx_http_request_t *r)
{
  ngx_http_upstream_t *upstream;
  ngx_str_t args;
  ngx_http_mobwrite_ctx_t *ctx;
  ngx_chain_t *in_chain, *out_chain;
  mobwrite_format_t format ;
  ngx_str_t mobwrite_request = ngx_null_string;
  static const ngx_str_t ARG_P = ngx_string("p");
  static const ngx_str_t ARG_Q = ngx_string("q");

  /* The form post body might have arrived in multiple buckets,
     so concatenate it into a single string to facilitate parsing */
  upstream = r->upstream;
  in_chain = upstream->request_bufs;
  if (r->method & NGX_HTTP_POST) {
    args = concatenate_text(r->pool, in_chain);
  }
  else {
    args = r->args;
  }

  /* Look for one of the form variables that the Mobwrite JavaScript client
     should have passed in: p=[Mobwrite message] or q=[Mobwrite message] */
	if (find_arg(r->pool, ARG_P, args, &mobwrite_request) == NGX_OK) {
    format = MOBWRITE_FMT_JS;
  }
  else if (find_arg(r->pool, ARG_Q, args, &mobwrite_request) == NGX_OK) {
    format = MOBWRITE_FMT_TXT;
  }
  else {
    return NGX_ERROR;
  }

  ctx = (ngx_http_mobwrite_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mobwrite_module);
  if (ctx == NULL) {
    ctx = (ngx_http_mobwrite_ctx_t *)ngx_palloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
      return NGX_ERROR;
    }
    ctx->format = format;
    ctx->response_started = 0;
    ngx_http_set_ctx(r, ctx, ngx_http_mobwrite_module);
  }

  /* Take the Mobwrite message that we received from the JavaScript client
     and pack it into a buffer chain to send to the Mobwrite daemon */
  out_chain = str_to_buffer_chain(mobwrite_request, r->pool);
  out_chain->buf->last_buf = 1;
  if (out_chain == NULL) {
    return NGX_ERROR;
  }
  r->upstream->request_bufs = out_chain;
  return NGX_OK;
}

/* Callback to reset state if nginx has to reinitialize the upstream request */
static ngx_int_t
ngx_http_mobwrite_reinit_request(ngx_http_request_t *r)
{
  return NGX_OK;
}

/* Callback to process the response header from the Mobwrite daemon */
static ngx_int_t
ngx_http_mobwrite_process_response_header(ngx_http_request_t *r)
{
  ngx_http_upstream_t *upstream = r->upstream;
  upstream->headers_in.status_n = 200;
  return NGX_OK;
}

/* Callback invoked if the request is aborted */
static void
ngx_http_mobwrite_abort_request(ngx_http_request_t *r)
{
  return;
}

/* Callback to finalize the Mobwrite request */
static void
ngx_http_mobwrite_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
  return;
}

/* Handler function that processes incoming requests destined for the Mobwrite daemon */
static ngx_int_t
ngx_http_mobwrite_handler(ngx_http_request_t *r)
{
  ngx_int_t rc;
  ngx_http_upstream_t *upstream;
  ngx_http_mobwrite_loc_conf_t *mobwrite_conf;

  /* Create an "upstream" object that tells nginx how to call the Mobwrite daemon */
  if ((rc = ngx_http_upstream_create(r)) != NGX_OK) {
    return rc;
  }
  upstream = r->upstream;
  upstream->schema.len = sizeof("mobwrite://") - 1;
  upstream->schema.data = (u_char *)"mobwrite://";
  upstream->output.tag = (ngx_buf_tag_t)&ngx_http_mobwrite_module;
  mobwrite_conf = (ngx_http_mobwrite_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_mobwrite_module);
  upstream->conf = &(mobwrite_conf->upstream);

  /* These callbacks will do the actual work of sending a request to the
     Mobwrite daemon and processing the reponse */
  upstream->create_request = ngx_http_mobwrite_create_request;
  upstream->reinit_request = ngx_http_mobwrite_reinit_request;
  upstream->process_header = ngx_http_mobwrite_process_response_header;
  upstream->abort_request = ngx_http_mobwrite_abort_request;
  upstream->finalize_request = ngx_http_mobwrite_finalize_request;

  /* Ask the nginx core to call our callbacks after the full POST body arrives. */
  rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
  if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    return rc;
  }
  return NGX_DONE;
}

/* Process the configuration directive "mobwrite_pass host:port" */
static char *
ngx_http_mobwrite_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_str_t *args;
  ngx_url_t url;
  ngx_http_core_loc_conf_t *core_loc_conf;
  ngx_http_mobwrite_loc_conf_t *mobwrite_conf = (ngx_http_mobwrite_loc_conf_t *)conf;
  args = cf->args->elts;
  url.url = args[1];
  url.default_port = 3017;
  url.uri_part = 1;
  url.no_resolve = 1;
  mobwrite_conf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0);
  core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  core_loc_conf->handler = ngx_http_mobwrite_handler;
  return NGX_CONF_OK;
}

/* Perform text transformations on the Mobwrite response so the client will understand it:
 * 1. Add a blank line to the end of the response.
 * 2. If the client has requested the Javascript output format,
 *    wrap the text in a JavaScript method call.
 */
static ngx_int_t
ngx_http_mobwrite_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_http_mobwrite_ctx_t *ctx;
  ngx_chain_t *next, *last = NULL;
  int last_buf;

  ctx = (ngx_http_mobwrite_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mobwrite_module);
  if ((ctx == NULL) || ((ctx->format != MOBWRITE_FMT_TXT) && (ctx->format != MOBWRITE_FMT_JS))) {
    /* Not a Mobwrite request, so move on to the next output filter */
    return ngx_http_next_body_filter(r, in);
  }

  if (ctx->format == MOBWRITE_FMT_JS) {
    js_escape(in, r->pool);
  }

  /* Determine whether this filter chain contains the end of the response. */
  last_buf = 0;
  for (next = in; next != NULL; next = next->next) {
    last = next;
    if (next->buf->last_buf) {
      last_buf = 1;
    }
  }

  /* If we have encountered the end of the response, append a blank line.
     If the client requested the JavaScript output format, generate the
     closing method call syntax too. */
  if (last_buf) {
    ngx_str_t text = ngx_string("\n");
    ngx_str_t js_text = ngx_string("\");\n");
    ngx_chain_t *post;
    if (ctx->format == MOBWRITE_FMT_JS) {
      post = str_to_buffer_chain(js_text, r->pool);
    }
    else {
      post = str_to_buffer_chain(text, r->pool);
    }
    last->buf->last_buf = 0;
    post->buf->last_buf = 1;
    last->next = post;
  }

  /* If the client requested the Javascript output format,
     wrap the text in a method call */
  if (!ctx->response_started) {
    if (ctx->format == MOBWRITE_FMT_JS) {
      ngx_str_t text = ngx_string("mobwrite.callback(\"");
      ngx_chain_t *pre = str_to_buffer_chain(text, r->pool);
      pre->next = in;
      in = pre;
    }
    ctx->response_started = 1;
  }

  /* Pass the buffer chain on to the next filter */
  return ngx_http_next_body_filter(r, in);
}

/* Install the filter to process Mobwrite response bodies */
static ngx_int_t
ngx_http_mobwrite_filter_init(ngx_conf_t *cf)
{
  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_mobwrite_body_filter;
  return NGX_OK;
}

/* Module context: definitions of nginx configuration plugin hooks */
static ngx_http_module_t ngx_http_mobwrite_module_ctx = {
  NULL,                                  /* preconfiguration */
  ngx_http_mobwrite_filter_init,         /* postconfiguration */

  NULL,                                  /* create main configuration */
  NULL,                                  /* init main configuration */

  NULL,                                  /* create server configuration */
  NULL,                                  /* merge server configuration */

  ngx_http_mobwrite_create_loc_conf,     /* create location configuration */
  ngx_http_mobwrite_merge_loc_conf       /* merge location configuration */  
};

/* Configuration commands for this module */
static ngx_command_t ngx_http_mobwrite_commands[] = {
  { ngx_string("mobwrite_pass"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_mobwrite_pass,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
	ngx_null_command
};

/* Module definition structure that tells nginx how to interact with this module */
ngx_module_t ngx_http_mobwrite_module = {
  NGX_MODULE_V1,
  &ngx_http_mobwrite_module_ctx,         /* module context */
  ngx_http_mobwrite_commands,            /* module directives */
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
