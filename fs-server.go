package main

import (
	"github.com/elico/go-shadowd"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/elico/go-metalink-parser"
	"github.com/elico/mux"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

//Config
var http_port *string
var debug *bool
var fs *string
var shadowd_addr *string
var shadowd_profileid *string
var shadowd_profilekey *string
var shadowd_debug *bool
var shadowd_rawdata *bool

//Global
var err error
var shadowServer shadowd.ShadowdConn

var internalerrorpage =`<!DOCTYPE html>
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

func dummyHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "dummmy handler")
}

func httpHandlerToHandlerMetalink(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		//If there is a metalink file and the downloaded file is not a metalink file
		// Then add couple meta links headers
		file := *fs + (strings.TrimPrefix(path.Clean(req.URL.Path), "/fs"))

		// not a dir
		// a file
		// doesn't have a meta4 or metalink ext
		// have the same filename with meta4 or metalink
		if !strings.HasSuffix(file, "/") && !strings.HasSuffix(file, ".meta4") && !strings.HasSuffix(file, ".metalink") {
			// Open\Read metalink file
			metalinkinfo, err := metalinks.ParseFile(file + ".metalink")
			if err != nil && err != io.EOF {
				fmt.Printf("Error: %v\n", err.Error())
			}

			// Add digest headers
			if len(metalinkinfo.Files.File) > 0 {
				res.Header().Add("Link", fmt.Sprintf("<%v>; rel=describedby; type=\"application/metalink4+xml\"", req.URL.Path+".metalink"))
				for _, v := range metalinkinfo.Files.File[0].Verification.Hashes {
					res.Header().Add("Digest", strings.ToUpper(v.Type)+"="+(base64.StdEncoding.EncodeToString([]byte(v.Text))))
				}
			}

			// Add metalink headers

			// If the request is a GET with "if modified hash XYZ" then
			// Compare to the metalink file and if matches then respond with a 304
		}
		next.ServeHTTP(res, req)
		return
	})
}

func unsupportedMethod(w http.ResponseWriter, r *http.Request) {
	cacheResponseFor(w, r, 600)
	http.Error(w, "Unsupported Method", 405)
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "Unsupported Method for this interface!!!")
}

func cacheResponseFor(w http.ResponseWriter, r *http.Request, seconds int) {
	cacheUntil := time.Now().UTC().Add(time.Duration(seconds) * time.Second).Format(http.TimeFormat)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(seconds))
	w.Header().Set("Expires", cacheUntil)
}

func dontCacheResponse(w http.ResponseWriter, r *http.Request) {
	cacheUntil := time.Now().UTC().Add(time.Duration(-3600) * time.Second).Format(http.TimeFormat)
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Header().Set("Expires", cacheUntil)
}

func httpHandlerToHandlerShadowd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		shodowdres, err := shadowServer.SendToShadowd(req)
		newmap := make(map[string]interface{})
		err = json.Unmarshal([]byte(shodowdres), &newmap)
		if err != nil {
			panic(err)
		}
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

func init() {
	debug = flag.Bool("debug", false, "Use \"1\" to enable")
	http_port = flag.String("http_port", "127.0.0.1:8080", "ip:port or plain \":port\" to listen on all IPs")
	shadowd_addr = flag.String("shadowd_addr", "127.0.0.1:9115", "ip:port of shadowd server")
	shadowd_profileid = flag.String("shadowd_profileid", "1", "Must be a number")
	shadowd_profilekey = flag.String("shadowd_profilekey", "102030", "It's a key to hash the data")
	shadowd_debug = flag.Bool("shadowd_debug", false, "Use \"1\" to enable")
	shadowd_rawdata = flag.Bool("shadowd_rawdata", false, "Log request raw data Use \"1\" to enable")

	fs = flag.String("fs", "/var/www/fs", "User interface files path")

	flag.Parse()

	var flagsMap = make(map[string]interface{})
	flagsMap["debug"] = *debug
	flagsMap["http_port"] = *http_port
	flagsMap["shadowd_addr"] = *shadowd_addr
	flagsMap["shadowd_profileid"] = *shadowd_profileid
	flagsMap["shadowd_profilekey"] = *shadowd_profilekey
	flagsMap["shadowd_debug"] = *shadowd_debug
	flagsMap["shadowd_rawdata"] = *shadowd_rawdata

	if *debug {
		fmt.Println("Config Variables:")
		for v, k := range flagsMap {
			fmt.Printf("\t%v => %v\n", v, k)
		}
	}

}

func main() {

	shadowServer = shadowd.ShadowdConn{ServerAddr: *shadowd_addr,
		ReadBody:   *shadowd_rawdata,
		ProfileId:  *shadowd_profileid,
		Logfile:    "",
		Debug:      *shadowd_debug,
		ProfileKey: *shadowd_profilekey,
	}
	router := mux.NewRouter().StrictSlash(true)

	//router.PathPrefixWithName("/fs/").Handler(httpHandlerToHandler(http.StripPrefix("/fs/", http.FileServer(http.Dir(*fs)))))
	router.PathPrefixWithName("/fs/").Handler(httpHandlerToHandlerShadowd(http.StripPrefix("/fs/", http.FileServer(http.Dir(*fs)))))

	err := http.ListenAndServe(*http_port, router)

	if strings.Contains(err.Error(), "resource temporarily unavailable") {
		fmt.Println("### unavaliable  ###")
		fmt.Println(err)
		return
	}
	if err != nil {
		panic(err.Error())
	}
}
