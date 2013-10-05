CodeMirror.defineMode("nginx",function(a){function b(a){var d,b={},c=a.split(" ");for(d=0;d<c.length;++d)b[c[d]]=!0;return b}function h(a,b){return g=b,a}function i(a,b){var f,g;return a.eatWhile(/[\w\$_]/),f=a.current(),c.propertyIsEnumerable(f)?"keyword":d.propertyIsEnumerable(f)?"variable-2":e.propertyIsEnumerable(f)?"string-2":(g=a.next(),"@"==g?(a.eatWhile(/[\w\\\-]/),h("meta",a.current())):"/"==g&&a.eat("*")?(b.tokenize=j,j(a,b)):"<"==g&&a.eat("!")?(b.tokenize=k,k(a,b)):"="!=g?"~"!=g&&"|"!=g||!a.eat("=")?'"'==g||"'"==g?(b.tokenize=l(g),b.tokenize(a,b)):"#"==g?(a.skipToEnd(),h("comment","comment")):"!"==g?(a.match(/^\s*\w*/),h("keyword","important")):/\d/.test(g)?(a.eatWhile(/[\w.%]/),h("number","unit")):/[,.+>*\/]/.test(g)?h(null,"select-op"):/[;{}:\[\]]/.test(g)?h(null,g):(a.eatWhile(/[\w\\\-]/),h("variable","variable")):h(null,"compare"):(h(null,"compare"),void 0))}function j(a,b){for(var d,c=!1;null!=(d=a.next());){if(c&&"/"==d){b.tokenize=i;break}c="*"==d}return h("comment","comment")}function k(a,b){for(var d,c=0;null!=(d=a.next());){if(c>=2&&">"==d){b.tokenize=i;break}c="-"==d?c+1:0}return h("comment","comment")}function l(a){return function(b,c){for(var e,d=!1;null!=(e=b.next())&&(e!=a||d);)d=!d&&"\\"==e;return d||(c.tokenize=i),h("string","string")}}var g,c=b("break return rewrite set accept_mutex accept_mutex_delay access_log add_after_body add_before_body add_header addition_types aio alias allow ancient_browser ancient_browser_value auth_basic auth_basic_user_file auth_http auth_http_header auth_http_timeout autoindex autoindex_exact_size autoindex_localtime charset charset_types client_body_buffer_size client_body_in_file_only client_body_in_single_buffer client_body_temp_path client_body_timeout client_header_buffer_size client_header_timeout client_max_body_size connection_pool_size create_full_put_path daemon dav_access dav_methods debug_connection debug_points default_type degradation degrade deny devpoll_changes devpoll_events directio directio_alignment empty_gif env epoll_events error_log eventport_events expires fastcgi_bind fastcgi_buffer_size fastcgi_buffers fastcgi_busy_buffers_size fastcgi_cache fastcgi_cache_key fastcgi_cache_methods fastcgi_cache_min_uses fastcgi_cache_path fastcgi_cache_use_stale fastcgi_cache_valid fastcgi_catch_stderr fastcgi_connect_timeout fastcgi_hide_header fastcgi_ignore_client_abort fastcgi_ignore_headers fastcgi_index fastcgi_intercept_errors fastcgi_max_temp_file_size fastcgi_next_upstream fastcgi_param fastcgi_pass_header fastcgi_pass_request_body fastcgi_pass_request_headers fastcgi_read_timeout fastcgi_send_lowat fastcgi_send_timeout fastcgi_split_path_info fastcgi_store fastcgi_store_access fastcgi_temp_file_write_size fastcgi_temp_path fastcgi_upstream_fail_timeout fastcgi_upstream_max_fails flv geoip_city geoip_country google_perftools_profiles gzip gzip_buffers gzip_comp_level gzip_disable gzip_hash gzip_http_version gzip_min_length gzip_no_buffer gzip_proxied gzip_static gzip_types gzip_vary gzip_window if_modified_since ignore_invalid_headers image_filter image_filter_buffer image_filter_jpeg_quality image_filter_transparency imap_auth imap_capabilities imap_client_buffer index ip_hash keepalive_requests keepalive_timeout kqueue_changes kqueue_events large_client_header_buffers limit_conn limit_conn_log_level limit_rate limit_rate_after limit_req limit_req_log_level limit_req_zone limit_zone lingering_time lingering_timeout lock_file log_format log_not_found log_subrequest map_hash_bucket_size map_hash_max_size master_process memcached_bind memcached_buffer_size memcached_connect_timeout memcached_next_upstream memcached_read_timeout memcached_send_timeout memcached_upstream_fail_timeout memcached_upstream_max_fails merge_slashes min_delete_depth modern_browser modern_browser_value msie_padding msie_refresh multi_accept open_file_cache open_file_cache_errors open_file_cache_events open_file_cache_min_uses open_file_cache_valid open_log_file_cache output_buffers override_charset perl perl_modules perl_require perl_set pid pop3_auth pop3_capabilities port_in_redirect postpone_gzipping postpone_output protocol proxy proxy_bind proxy_buffer proxy_buffer_size proxy_buffering proxy_buffers proxy_busy_buffers_size proxy_cache proxy_cache_key proxy_cache_methods proxy_cache_min_uses proxy_cache_path proxy_cache_use_stale proxy_cache_valid proxy_connect_timeout proxy_headers_hash_bucket_size proxy_headers_hash_max_size proxy_hide_header proxy_ignore_client_abort proxy_ignore_headers proxy_intercept_errors proxy_max_temp_file_size proxy_method proxy_next_upstream proxy_pass_error_message proxy_pass_header proxy_pass_request_body proxy_pass_request_headers proxy_read_timeout proxy_redirect proxy_send_lowat proxy_send_timeout proxy_set_body proxy_set_header proxy_ssl_session_reuse proxy_store proxy_store_access proxy_temp_file_write_size proxy_temp_path proxy_timeout proxy_upstream_fail_timeout proxy_upstream_max_fails random_index read_ahead real_ip_header recursive_error_pages request_pool_size reset_timedout_connection resolver resolver_timeout rewrite_log rtsig_overflow_events rtsig_overflow_test rtsig_overflow_threshold rtsig_signo satisfy secure_link_secret send_lowat send_timeout sendfile sendfile_max_chunk server_name_in_redirect server_names_hash_bucket_size server_names_hash_max_size server_tokens set_real_ip_from smtp_auth smtp_capabilities smtp_client_buffer smtp_greeting_delay so_keepalive source_charset ssi ssi_ignore_recycled_buffers ssi_min_file_chunk ssi_silent_errors ssi_types ssi_value_length ssl ssl_certificate ssl_certificate_key ssl_ciphers ssl_client_certificate ssl_crl ssl_dhparam ssl_engine ssl_prefer_server_ciphers ssl_protocols ssl_session_cache ssl_session_timeout ssl_verify_client ssl_verify_depth starttls stub_status sub_filter sub_filter_once sub_filter_types tcp_nodelay tcp_nopush thread_stack_size timeout timer_resolution types_hash_bucket_size types_hash_max_size underscores_in_headers uninitialized_variable_warn use user userid userid_domain userid_expires userid_mark userid_name userid_p3p userid_path userid_service valid_referers variables_hash_bucket_size variables_hash_max_size worker_connections worker_cpu_affinity worker_priority worker_processes worker_rlimit_core worker_rlimit_nofile worker_rlimit_sigpending worker_threads working_directory xclient xml_entities xslt_stylesheet xslt_typesdrew@li229-23"),d=b("http mail events server types location upstream charset_map limit_except if geo map"),e=b("include root server server_name listen internal proxy_pass memcached_pass fastcgi_pass try_files"),f=a.indentUnit;return{startState:function(a){return{tokenize:i,baseIndent:a||0,stack:[]}},token:function(a,b){var c,d;return a.eatSpace()?null:(g=null,c=b.tokenize(a,b),d=b.stack[b.stack.length-1],"hash"==g&&"rule"==d?c="atom":"variable"==c&&("rule"==d?c="number":d&&"@media{"!=d||(c="tag")),"rule"==d&&/^[\{\};]$/.test(g)&&b.stack.pop(),"{"==g?"@media"==d?b.stack[b.stack.length-1]="@media{":b.stack.push("{"):"}"==g?b.stack.pop():"@media"==g?b.stack.push("@media"):"{"==d&&"comment"!=g&&b.stack.push("rule"),c)},indent:function(a,b){var c=a.stack.length;return/^\}/.test(b)&&(c-="rule"==a.stack[a.stack.length-1]?2:1),a.baseIndent+c*f},electricChars:"}"}}),CodeMirror.defineMIME("text/nginx","text/x-nginx-conf");