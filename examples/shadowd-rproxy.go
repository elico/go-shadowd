// Based on some of the from at the url: http://www.darul.io/post/2015-07-22_go-lang-simple-reverse-proxy
//
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/elico/go-shadowd"
	"net/http"
	"net/http/httputil"
	"net/url"
)

var shadowd_addr *string
var shadowd_profileid *string
var shadowd_profilekey *string
var shadowd_debug *bool
var shadowd_rawdata *bool

var shadowServer shadowd.ShadowdConn

var internalerrorpage = `<!DOCTYPE html>
<html>
<head>
<title>Error</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>An error occurred.</h1>
<p>Sorry, the page you are looking for is currently unavailable.<br/>
Please try again later.</p>
<p>If you are the system administrator of this resource then you should check
the error log for details.</p>
<p><em>Faithfully yours, WebServer.</em></p>
</body>
</html>
`

// our RerverseProxy object
type Prox struct {
	// target url of reverse proxy
	target *url.URL
	// instance of Go ReverseProxy thatwill do the job for us
	proxy *httputil.ReverseProxy
}

// small factory
func New(target string) *Prox {
	url, _ := url.Parse(target)
	// you should handle error on parsing
	return &Prox{target: url, proxy: httputil.NewSingleHostReverseProxy(url)}
}

func (p *Prox) handle(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("X-Real-IP", r.RemoteAddr)
	// call to magic method from ReverseProxy object
	p.proxy.ServeHTTP(w, r)
}

func httpHandlerToHandlerShadowd(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		shodowdres, err := shadowServer.SendToShadowd(req)
		newmap := make(map[string]interface{})
		err = json.Unmarshal([]byte(shodowdres), &newmap)
		if err != nil {
			panic(err)
		}
		res.Header().Set("X-Ngtech-Proxy", "Shadower")
		switch int(newmap["status"].(float64)) {
		case shadowd.STATUS_OK:
			fmt.Println("Request reported, OK")
		case shadowd.STATUS_BAD_REQUEST:
			res.Header().Set("Content-Type", "text/html")
			res.WriteHeader(400)
			res.Write([]byte(internalerrorpage))
			return
		case shadowd.STATUS_BAD_SIGNATURE:
			res.Header().Set("Content-Type", "text/html")
			res.WriteHeader(500)
			res.Write([]byte(internalerrorpage))
			return
		case shadowd.STATUS_BAD_JSON:
			res.Header().Set("Content-Type", "text/html")
			res.WriteHeader(500)
			res.Write([]byte(internalerrorpage))
			return
		case shadowd.STATUS_ATTACK:
			fmt.Println("This is an attack, needs to take action!")
			res.Header().Set("Content-Type", "text/html")
			res.WriteHeader(500)
			res.Write([]byte(internalerrorpage))
			return
		case shadowd.STATUS_CRITICAL_ATTACK:
			fmt.Println("This is a critical attack, needs to take action!")
			res.Header().Set("Content-Type", "text/html")
			res.WriteHeader(500)
			res.Write([]byte(internalerrorpage))
			return
		default:
			fmt.Println("Something werid happen, response code => ", int(newmap["status"].(float64)))
			res.Header().Set("Content-Type", "text/html")
			res.WriteHeader(500)
			res.Write([]byte(internalerrorpage))
			return
		}
		next.ServeHTTP(res, req)
		return
	})
}

func main() {
	// come constants and usage helper
	const (
		defaultPort        = ":80"
		defaultPortUsage   = "default server port, ':80', ':8080'..."
		defaultTarget      = "http://127.0.0.1:8080"
		defaultTargetUsage = "default redirect url, 'http://127.0.0.1:8080'"
	)

	// flags
	port := flag.String("port", defaultPort, defaultPortUsage)
	url := flag.String("url", defaultTarget, defaultTargetUsage)

	shadowd_addr = flag.String("shadowd_addr", "127.0.0.1:9115", "ip:port of shadowd server")
	shadowd_profileid = flag.String("shadowd_profileid", "1", "Must be a number")
	shadowd_profilekey = flag.String("shadowd_profilekey", "102030", "It's a key to hash the data")
	shadowd_debug = flag.Bool("shadowd_debug", false, "Use \"1\" to enable")
	shadowd_rawdata = flag.Bool("shadowd_rawdata", false, "Log request raw data Use \"1\" to enable")

	flag.Parse()
	shadowServer = shadowd.ShadowdConn{ServerAddr: *shadowd_addr,
		ReadBody:   *shadowd_rawdata,
		ProfileId:  *shadowd_profileid,
		Logfile:    "",
		Debug:      *shadowd_debug,
		ProfileKey: *shadowd_profilekey,
	}

	fmt.Printf("server will run on : %s\n", *port)
	fmt.Printf("redirecting to :%s\n", *url)

	// proxy
	proxy := New(*url)

	// server
	http.HandleFunc("/", httpHandlerToHandlerShadowd(proxy.handle))
	http.ListenAndServe(*port, nil)
}
