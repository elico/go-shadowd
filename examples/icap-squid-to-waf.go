// This tool is very helpful for GET requests logging and also helps
// to understand and analyze better mis-caching issues.
// To use with squid add the next to the squid.conf
// icap_enable on
// adaptation_send_client_ip on
// icap_service service_req reqmod_precache icap://127.0.0.1:1344/shadower/
// acl ICAP method GET HEAD
// adaptation_access service_req allow ICAP
// adaptation_access service_req deny all
//
// Example startup command: /opt/icap-to-waf/icap-squid-to-waf -listen=:1344 -shadowd_addr=127.0.0.1:9115 -shadowd_profileid=3 -shadowd_profilekey=102030
//
package main

import (
	"flag"
	"fmt"
	"github.com/elico/icap"
	"github.com/elico/go-shadowd"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"encoding/json"
)

var ISTag = "\"Shadower\""
var debug *bool
var address *string
var maxConnections *string
var fullOverride = false
var err error


var shadowd_addr *string
var shadowd_profileid *string
var shadowd_profilekey *string
var shadowd_debug *bool
var shadowd_rawdata *bool
var shadowServer shadowd.ShadowdConn

const internalerrorpage = `<!DOCTYPE html>
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
<p><em>Faithfully yours, Shadower(ICAP+ShadowD WAF).</em></p>
</body>
</html>
`

func wrongMethod(req *icap.Request) bool {
	if *debug {
		fmt.Println("Checking Request method => ", req.Request.Method)
	}

	if req.Request.Method == "CONNECT" {
		return true
	} else {
		return false
	}
}

func toShadowD(w icap.ResponseWriter, req *icap.Request) {
	local_debug := false
	if strings.Contains(req.URL.RawQuery, "debug=1") {
		local_debug = true
	}

	h := w.Header()
	h.Set("ISTag", ISTag)
	h.Set("Service", "Shadower ICAP to WAF Connector")

	if *debug {
		fmt.Fprintln(os.Stderr, "Printing the full ICAP request")
		fmt.Fprintln(os.Stderr, req)
		fmt.Fprintln(os.Stderr, req.Request)
		fmt.Fprintln(os.Stderr, req.Response)
	}
	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "REQMOD")
		h.Set("Options-TTL", "1800")
		h.Set("Allow", "204, 206")
		h.Set("Preview", "0")
		h.Set("Transfer-Preview", "*")
		h.Set("Max-Connections", *maxConnections)
		h.Set("X-Include", "X-Client-Ip, X-Authenticated-Groups, X-Authenticated-User, X-Subscriber-Id")
		w.WriteHeader(200, nil, false)
	case "REQMOD":
		modified := false
		nullBody := false
		allow206 := false
		allow204 := false
		xclientip := false
		
		if _, allow204Exists := req.Header["Allow"]; allow204Exists {
			if strings.Contains(req.Header["Allow"][0], "204") {
				allow204 = true
			}
		}
		
		if _, allow206Exists := req.Header["Allow"]; allow206Exists {
			if strings.Contains(req.Header["Allow"][0], "206") {
				allow206 = true
			}
		}

		if _, xclientipExists := req.Header["X-Client-Ip"]; xclientipExists {
			if len(req.Header["X-Client-Ip"][0]) > 1 {
				xclientip = true
			}
		}
		
		if _, encapsulationExists := req.Header["Encapsulated"]; encapsulationExists {
			if strings.Contains(req.Header["Encapsulated"][0], "null-body=") {
				nullBody = true
			}
		}

		if *debug || local_debug {
			for k, v := range req.Header {
				fmt.Fprintln(os.Stderr, "The ICAP headers:")
				fmt.Fprintln(os.Stderr, "key size:", len(req.Header[k]))
				fmt.Fprintln(os.Stderr, "key:", k, "value:", v)
			}
		}

		_, _, _, _ = nullBody, allow206, modified, allow204
		if xclientip {
			req.Request.RemoteAddr = req.Header["X-Client-Ip"][0]
		}
		
		if wrongMethod(req) {
			if *debug {
				fmt.Println("This request has a", req.Request.Method, "method which is not being analyzed")
			}
			w.WriteHeader(204, nil, false)
			return
		}

		if *debug || local_debug {
			for k, v := range req.Request.Header {
				fmt.Fprintln(os.Stderr, "key:", k, "value:", v)
			}
		}

		// Send the request to ShadowD
		// If an attack(5,6) was declared then send a custom 500 page
		// If OK then send a 204 back
		var resStatus = 1
		shodowdres, err := shadowServer.SendToShadowd(req.Request)
		newmap := make(map[string]interface{})
		err = json.Unmarshal([]byte(shodowdres), &newmap)
		if err != nil {
			panic(err)
		}
		
		switch int(newmap["status"].(float64)) {
		case shadowd.STATUS_OK:
			if *debug || local_debug {
				fmt.Println("Request reported, OK")
			}
			w.WriteHeader(204, nil, false)
			return
		case shadowd.STATUS_BAD_REQUEST:
			resStatus = 400
		case shadowd.STATUS_BAD_SIGNATURE:
			resStatus = 503
		case shadowd.STATUS_BAD_JSON:
			resStatus = 504
		case shadowd.STATUS_ATTACK:
			resStatus = 505
		case shadowd.STATUS_CRITICAL_ATTACK:
			resStatus = 506
		default:
			resStatus = 500
		}
		
		resp := new(http.Response)
		resp.Status = "Internal Server Error"
		resp.StatusCode = resStatus
		resp.Proto = req.Request.Proto
		resp.ProtoMajor = req.Request.ProtoMajor
		resp.ProtoMinor = req.Request.ProtoMinor
		resp.Request = req.Request
		myHeaderMap := make(map[string][]string)
		resp.Header = myHeaderMap
		resp.Header.Set("X-Ngtech-Proxy", "Shadower")
		resp.Header.Set("X-Shadower", strconv.Itoa(resStatus))
		resp.Header.Set("Content-Type", "text/html")
		resp.Header.Set("Content-Length", strconv.Itoa(len(internalerrorpage)))
		w.WriteHeader(200, resp, true)
		io.WriteString(w, internalerrorpage)
		return

		if *debug {
			fmt.Println("end of the line 204 response!.. Shouldn't happen.")
		}
		w.WriteHeader(204, nil, false)
		return
	case "RESPMOD":
		w.WriteHeader(204, nil, false)
		return
	default:
		w.WriteHeader(405, nil, false)
		if *debug || local_debug {
			fmt.Fprintln(os.Stderr, "Invalid request method")
		}
	}
}

func defaultIcap(w icap.ResponseWriter, req *icap.Request) {
	local_debug := false
	if strings.Contains(req.URL.RawQuery, "debug=1") {
		local_debug = true
	}

	h := w.Header()
	h.Set("ISTag", ISTag)
	h.Set("Service", "Shadower default ICAP service")

	if *debug || local_debug {
		fmt.Fprintln(os.Stderr, "Printing the full ICAP request")
		fmt.Fprintln(os.Stderr, req)
		fmt.Fprintln(os.Stderr, req.Request)
	}
	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "REQMOD, RESPMOD")
		h.Set("Options-TTL", "1800")
		h.Set("Allow", "204")
		h.Set("Preview", "0")
		h.Set("Transfer-Preview", "*")
		h.Set("Max-Connections", *maxConnections)
		h.Set("This-Server", "Default ICAP url which bypass all requests adaptation")
		h.Set("X-Include", "X-Client-IP, X-Authenticated-Groups, X-Authenticated-User, X-Subscriber-Id, X-Server-IP")
		w.WriteHeader(200, nil, false)
	case "REQMOD":
		if *debug || local_debug {
			fmt.Fprintln(os.Stderr, "Default REQMOD, you should use the apropriate ICAP service URL")
		}
		w.WriteHeader(204, nil, false)
	case "RESPMOD":
		if *debug || local_debug {
			fmt.Fprintln(os.Stderr, "Default RESPMOD, you should use the apropriate ICAP service URL")
		}
		w.WriteHeader(204, nil, false)
	default:
		w.WriteHeader(405, nil, false)
		if *debug || local_debug {
			fmt.Fprintln(os.Stderr, "Invalid request method")
		}
	}
}

func init() {
	fmt.Fprintln(os.Stderr, "Shadower WAF connector ICAP service")

	debug = flag.Bool("debug", false, "Debug mode can be \"1\" or \"0\" for no")
	address = flag.String("listen", "127.0.0.1:1344", "Listening address for the ICAP service")
	maxConnections = flag.String("maxcon", "4000", "Maximum number of connections for the ICAP service")
	shadowd_addr = flag.String("shadowd_addr", "127.0.0.1:9115", "ip:port of shadowd server")
	shadowd_profileid = flag.String("shadowd_profileid", "1", "Must be a number")
	shadowd_profilekey = flag.String("shadowd_profilekey", "102030", "It's a key to hash the data")
	shadowd_debug = flag.Bool("shadowd_debug", false, "Use \"1\" to enable")
	//shadowd_rawdata = flag.Bool("shadowd_rawdata", false, "Log request raw data Use \"1\" to enable")

	flag.Parse()
	
}

func main() {
	fmt.Fprintln(os.Stderr, "Starting Shadower WAF connector ICAP service :D")

	if *debug {
		fmt.Fprintln(os.Stderr, "Config Variables:")
		fmt.Fprintln(os.Stderr, "Debug: => "+strconv.FormatBool(*debug))
		fmt.Fprintln(os.Stderr, "Listen Address: => "+*address)
		fmt.Fprintln(os.Stderr, "Maximum number of Connections: => "+*maxConnections)

	}
	
	shadowServer = shadowd.ShadowdConn{ServerAddr: *shadowd_addr,
		ReadBody:   false, // Disabled due to the structure of the ICAP service that doesn't implement bodies hanlding properly.
		ProfileId:  *shadowd_profileid,
		Logfile:    "",
		Debug:      *shadowd_debug,
		ProfileKey: *shadowd_profilekey,
	}
	
	icap.HandleFunc("/shadower/", toShadowD)
	icap.HandleFunc("/", defaultIcap)
	err := icap.ListenAndServe(*address, nil)
	panic(err)
}
