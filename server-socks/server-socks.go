package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/armon/go-socks5"
	"github.com/foomo/htpasswd"
	"github.com/patrickmn/go-cache"
	"github.com/spaolacci/murmur3"
	"go.uber.org/zap"

	"golang.org/x/crypto/bcrypt"

	"gopkg.in/yaml.v2"
)

type Destination struct {
	Users []string
	Ports []int
}

func main() {

	flagAddr := flag.String("addr", "", "where to listen like 127.0.0.1:8000")
	flagHtpasswdFile := flag.String("auth", "", "basic auth file")
	flagDestinationsFile := flag.String("destinations", "", "file with destinations config")
	flagCert := flag.String("cert", "", "path to server cert.pem")
	flagKey := flag.String("key", "", "path to server key.pem")
	flagDisableBasicAuthCaching := flag.Bool("disable-basic-auth-caching", false, "if set disables caching of basic auth user and password")
	flag.Parse()

	// 解析配置文件
	destinationBytes, err := ioutil.ReadFile(*flagDestinationsFile)
	if err != nil {
		fmt.Printf("can not read destinations config, 错误：%v", err)
		return
	}
	destinations := map[string]*Destination{}
	err = yaml.Unmarshal(destinationBytes, destinations)

	if err != nil {
		fmt.Printf("can not parse destinations, 错误：%v", err)
		return
	}

	passwordHashes, err := htpasswd.ParseHtpasswdFile(*flagHtpasswdFile)
	if err != nil {
		fmt.Printf("basic auth file sucks, 错误：%v", err)
		return
	}
	credentials := Credentials{disableCaching: *flagDisableBasicAuthCaching, htpasswd: passwordHashes}

	suxx5, err := newAuthenticator(destinations)
	if err != nil {
		fmt.Printf("newAuthenticator failed, 错误：%v", err)
		return
	}

	autenticator := socks5.UserPassAuthenticator{Credentials: credentials}
	conf := &socks5.Config{
		Rules:       suxx5,
		AuthMethods: []socks5.Authenticator{autenticator},
	}
	server, err := socks5.New(conf)
	if err != nil {
		fmt.Printf("socks5.New failed, 错误：%v", err)
		return
	}

	cert, err := tls.LoadX509KeyPair(*flagCert, *flagKey)

	if err != nil {
		fmt.Printf("could not load server key pair, 错误：%v", err)
		return
	}
	listener, err := tls.Listen("tcp", *flagAddr, &tls.Config{Certificates: []tls.Certificate{cert}})

	if err != nil {
		fmt.Printf("could not listen for tcp / tls, 错误：%v", err)
		return
	}
	server.Serve(listener)
}

type Credentials struct {
	disableCaching bool
	htpasswd       map[string]string
}
type authenticator struct {
	Destinations  map[string]*Destination
	resolvedNames map[string][]string
}

func newAuthenticator(destinations map[string]*Destination) (*authenticator, error) {
	sa := &authenticator{
		Destinations: destinations,
	}
	names := make([]string, 0, len(destinations))
	for name := range destinations {
		names = append(names, name)
	}

	resolvedNames, err := resolveNames(names)
	if err != nil {
		return nil, err
	}
	sa.resolvedNames = resolvedNames

	go func() {
		time.Sleep(time.Second * 10)

		resolvedNames, err := resolveNames(names)
		if err == nil {
			sa.resolvedNames = resolvedNames
		} else {
			fmt.Printf("could not resolve names, 错误：%v", err)
		}
	}()
	return sa, nil
}

func resolveNames(names []string) (map[string][]string, error) {
	newResolvedNames := map[string][]string{}
	for _, name := range names {
		addrs, err := net.LookupHost(name)
		if err != nil {
			return nil, err
		}
		newResolvedNames[name] = addrs
	}
	return newResolvedNames, nil
}

var basicAuthCache = cache.New(120*time.Second, 60*time.Minute)

const defaultBasicAuthTTL = 90 * time.Second

func (s Credentials) Valid(user, password string) bool {
	hashedPW := s.htpasswd[user]
	hashedPWb := []byte(hashedPW)
	plainPWb := []byte(password)

	if s.disableCaching {
		return nil == bcrypt.CompareHashAndPassword(hashedPWb, plainPWb)
	}

	hasher := murmur3.New64()

	cachedPass, inCache := basicAuthCache.Get(hashedPW)
	if !inCache {
		ok := nil == bcrypt.CompareHashAndPassword(hashedPWb, plainPWb)
		if !ok {
			return false
		}

		hasher.Write(plainPWb)
		basicAuthCache.Set(hashedPW, string(hasher.Sum(nil)), defaultBasicAuthTTL)
		return true
	}

	hasher.Write(plainPWb)
	if cachedPass.(string) != string(hasher.Sum(nil)) {
		return nil == bcrypt.CompareHashAndPassword(hashedPWb, plainPWb)
	}

	return true
}

func (sa *authenticator) Allow(ctx context.Context, req *socks5.Request) (newCtx context.Context, allowed bool) {
	allowed = false
	newCtx = ctx
	zapTo := zap.String("to", req.DestAddr.String())
	zapUser := zap.String("for", req.AuthContext.Payload["Username"])

	for name, ips := range sa.resolvedNames {
		zapName := zap.String("name", name)
		for _, ip := range ips {
			if ip == req.DestAddr.IP.String() {
				destination, destinationOK := sa.Destinations[name]
				if destinationOK {
					for _, allowedPort := range destination.Ports {
						if allowedPort == req.DestAddr.Port {
							if len(destination.Users) == 0 {
								allowed = true
							}
							if !allowed {
								userNameInContext, userNameInContextOK := req.AuthContext.Payload["Username"]
								if !userNameInContextOK {
									// explicit user expected, but not found
									fmt.Printf("denied - no user found, 错误：%v, %v", zapName, zapTo)

									return
								}
								for _, userName := range destination.Users {
									if userName == userNameInContext {
										allowed = true
										break
									}
								}
								if !allowed {
									fmt.Printf("denied, 错误：%v, %v, %v", zapName, zapTo, zapUser)

									return
								}
							}
							if allowed {
								fmt.Printf("allowed：%v, %v, %v", zapName, zapTo, zapUser)

								allowed = true
								return
							}
						}
					}
				}
			}
		}
	}
	fmt.Printf("denied, 错误：%v, %v", zapTo, zapUser)

	return
}
