# hello-socks

学习socks项目，试验https://github.com/foomo/tlssocks 下的功能

其中client-socks运行在windows系统，server-socks运行在linux系统


在linux下生成key
openssl req -newkey rsa:2048 -nodes -keyout ./certificate.key -subj "/C=DE/ST=Bavaria/L=Munich/O=foomo/CN=192.168.74.128/" -out ./certificate.csr

注意，证书不支持ip,如果本地测试需要给ip取别如
echo subjectAltName=IP:192.168.74.128 > extfile.cnf

下面导出证书用到了别名
openssl x509 -req -extfile <(printf "subjectAltName=DNS:192.168.74.128/,DNS:localhost,DNS:127.0.0.1") -days 365 -signkey ./certificate.key -in ./certificate.csr -extfile extfile.cnf -out ./certificate.crt
