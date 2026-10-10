FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY favicon.ico favicon.svg favicon-16x16.png favicon-32x32.png apple-touch-icon.png icon-192.png icon-512.png site.webmanifest /usr/share/nginx/html/
EXPOSE 80
