package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io/ioutil"
	"net"
	"time"
	"util"

	"socks5"

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

	log, _ := zap.NewProduction()
	defer log.Sync()

	flagAddr := flag.String("addr", "0.0.0.0:8000", "where to listen like 127.0.0.1:8000")
	flagHtpasswdFile := flag.String("auth", "./users.htpasswd", "basic auth file")
	flagDestinationsFile := flag.String("destinations", "destinations.yaml", "file with destinations config")
	flagCert := flag.String("cert", "certificate.crt", "path to server cert.pem")
	flagKey := flag.String("key", "certificate.key", "path to server key.pem")
	flagDisableBasicAuthCaching := flag.Bool("disable-basic-auth-caching", false, "if set disables caching of basic auth user and password")
	flag.Parse()

	destinationBytes, err := ioutil.ReadFile(*flagDestinationsFile)
	util.TryFatal(log, err, "can not read destinations config")

	destinations := map[string]*Destination{}

	util.TryFatal(log, yaml.Unmarshal(destinationBytes, destinations), "can not parse destinations")

	passwordHashes, err := htpasswd.ParseHtpasswdFile(*flagHtpasswdFile)
	util.TryFatal(log, err, "basic auth file sucks")
	credentials := Credentials{disableCaching: *flagDisableBasicAuthCaching, htpasswd: passwordHashes}

	suxx5, err := newAuthenticator(log, destinations)
	util.TryFatal(log, err, "newAuthenticator failed")

	autenticator := socks5.UserPassAuthenticator{Credentials: credentials}

	conf := &socks5.Config{
		Rules:       suxx5,
		AuthMethods: []socks5.Authenticator{autenticator},
	}
	server, err := socks5.New(conf)
	util.TryFatal(log, err, "socks5.New failed")

	log.Info(
		"starting tls server",
		zap.String("addr", *flagAddr),
		zap.String("cert", *flagCert),
		zap.String("key", *flagKey),
	)

	cert, err := tls.LoadX509KeyPair(*flagCert, *flagKey)
	util.TryFatal(log, err, "could not load server key pair")

	listener, err := tls.Listen("tcp", *flagAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
	util.TryFatal(log, err, "could not listen for tcp / tls", zap.String("addr", *flagAddr))

	util.TryFatal(log, server.Serve(listener), "server failed")
}

const defaultBasicAuthTTL = 90 * time.Second

var basicAuthCache = cache.New(120*time.Second, 60*time.Minute)

type Credentials struct {
	disableCaching bool
	htpasswd       map[string]string
}

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

type authenticator struct {
	log           *zap.Logger
	Destinations  map[string]*Destination
	resolvedNames map[string][]string
}

func newAuthenticator(log *zap.Logger, destinations map[string]*Destination) (*authenticator, error) {
	sa := &authenticator{
		log:          log,
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
			log.Warn("could not resolve names", zap.Error(err))
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
									sa.log.Info("denied - no user found", zapName, zapTo)
									return
								}
								for _, userName := range destination.Users {
									if userName == userNameInContext {
										allowed = true
										break
									}
								}
								if !allowed {
									sa.log.Info("denied", zapName, zapTo, zapUser)
									return
								}
							}
							if allowed {
								sa.log.Info("allowed", zapName, zapTo, zapUser)

								allowed = true
								return
							}
						}
					}
				}
			}
		}
	}
	sa.log.Info("denied", zapTo, zapUser)
	return
}
