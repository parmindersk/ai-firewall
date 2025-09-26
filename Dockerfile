FROM openresty/openresty:1.27.1.2-0-bookworm

COPY conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY conf/aif.lua    /usr/local/openresty/nginx/conf/aif.lua

EXPOSE 8080
CMD ["openresty", "-g", "daemon off;"]
