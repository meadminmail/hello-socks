# hello-socks

学习socks项目，试验https://github.com/foomo/tlssocks 下的功能

其中client-socks运行在windows系统，server-socks运行在linux系统


在linux下生成key
openssl req -newkey rsa:2048 -nodes -keyout ./certificate.key -subj "/C=DE/ST=Bavaria/L=Munich/O=foomo/CN=192.168.74.128/" -out ./certificate.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:192.168.74.128/,DNS:localhost,DNS:127.0.0.1") -days 365 -signkey ./certificate.key -in ./certificate.csr -out ./certificate.crt
