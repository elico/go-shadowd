// This package gives the option for a golang based http service to
// send http requests for analysis against the shadowd WAF.
// Examples at: https://github.com/elico/go-shadowd/tree/master/examples
//
package shadowd

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

// Global default settings constants
// All STATUS_X are describing an analysis result.
const (
	SHADOWD_CONNECTOR_VERSION        = "2.0.1-go"
	SHADOWD_CONNECTOR_CONFIG         = "/etc/shadowd/go-connector.ini"
	SHADOWD_CONNECTOR_CONFIG_SECTION = "shadowd_go"
	SHADOWD_LOG                      = "/var/log/shadowd.log"
	STATUS_OK                        = 1
	STATUS_BAD_REQUEST               = 2
	STATUS_BAD_SIGNATURE             = 3
	STATUS_BAD_JSON                  = 4
	STATUS_ATTACK                    = 5
	STATUS_CRITICAL_ATTACK           = 6
)

var VERSION = "2.0.1"

// A shadowd connection, this allows to send a request for analysis.
type ShadowdConn struct {
	ServerAddr    string
	ReadBody      bool
	UpperCookies  bool
	ProfileId     string
	ProfileKey    string
	Logfile       string
	Debug         bool
	LogFullCookie bool
}

func escapeKey(key string) string {
	newstr := strings.Replace(key, "/", "\\/", -1)
	newstr = strings.Replace(newstr, "|", "\\|", -1)
	return newstr
}

func unescapeKey(key string) string {
	newstr := strings.Replace(key, "\\\\", "\\", -1)
	newstr = strings.Replace(newstr, "\\|", "|", -1)
	return newstr
}

// Sends an http request to processing on the shadowd service.
// Returns a json object in a string format with the analysis result.
// The json "status" key is an integer(float64 when json parses it) that
// reflect the result of the test ranging from 1 to 6.
// 1 means that it is ok to pass the request to the origin server
// 5 and 6 means that the requester or the request was identified as an attack.
// The error is always nil unless some special parsing or communication happen.
// It is up to the developer what to do for each error and status code.
func (serverconn *ShadowdConn) SendToShadowd(req *http.Request) (string, error) {
	newmap := make(map[string]interface{})
	inputmap := make(map[string]string)
	newmap["version"] = SHADOWD_CONNECTOR_VERSION
	newmap["client_ip"] = strings.Split(req.RemoteAddr, ":")[0]
	newmap["caller"] = req.URL.Path
	newmap["resource"] = req.URL.Path

	inputmap["SERVER|HTTP_REMOTEADDR"] = req.RemoteAddr

	for k, v := range req.URL.Query() {
		for _, s := range v {
			inputmap[req.Method+"|"+escapeKey(k)] = s
		}
	}

	cookie := req.Cookies()
	for _, v := range cookie {
		if serverconn.UpperCookies {
			inputmap["COOKIE|"+escapeKey(strings.ToUpper(v.Name))] = v.Value
		} else {
			inputmap["COOKIE|"+escapeKey(v.Name)] = v.Value
		}
	}
	if serverconn.LogFullCookie {
		inputmap["SERVER|HTTP_COOKIE"] = ""
		for _, v := range cookie {
			inputmap["SERVER|HTTP_COOKIE"] = inputmap["SERVER|HTTP_COOKIE"] + v.Name + "=" + v.Value + "; "
		}
		if len(inputmap["SERVER|HTTP_COOKIE"]) == 0 {
			delete(inputmap, "SERVER|HTTP_COOKIE")
		}
	}
	headers := req.Header
	for k, v := range headers {
		inputmap["SERVER|HTTP_"+escapeKey(strings.Replace(strings.ToUpper(k), "-", "_", -1))] = strings.Join(v, "")
	}

	if req.Method != "GET" && serverconn.ReadBody {
		contents, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return "", err
		} else {
			inputmap["DATA|raw"] = string(contents)
			// Ne need to make the body readable again
			req.Body = ioutil.NopCloser(bytes.NewBufferString(inputmap["DATA|raw"]))
		}
	}
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil && serverconn.Debug {
		fmt.Println("Error parsing server host+port", err)
	}
	if host != "" {
		inputmap["SERVER|HTTP_HOST"] = host
		inputmap["SERVER|HTTP_PORT"] = port
	} else {
		inputmap["SERVER|HTTP_HOST"] = req.Host
	}
	newmap["input"] = inputmap

	jsonData, err := json.Marshal(inputmap)
	if err != nil {
		fmt.Println("JSON marshaling failed:", err)
		return "", err
	}

	hash := make(map[string]string)

	//mac := hmac.New(sha256.New, nil)
	//mac.Write([]byte(unescapeKey(string(jsonData))))
	//expectedMAC := hex.EncodeToString(mac.Sum(nil))
	//hash["sha256"] = expectedMAC

	newmap["hashes"] = hash

	jsonData, err = json.Marshal(newmap)
	if err != nil {
		fmt.Println("JSON marshaling failed:", err)
		return "", err
	}

	mac := hmac.New(sha256.New, []byte(serverconn.ProfileKey))
	newjson := []byte(unescapeKey(string(jsonData)))
	mac.Write(newjson)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	if serverconn.Debug {
		fmt.Printf("%v\n%v\n%v\n", serverconn.ProfileId, expectedMAC, string(newjson))
	}
	//send the fomratted string into the shadowd server at port 9115

	tcpAddr, err := net.ResolveTCPAddr("tcp", serverconn.ServerAddr)
	if err != nil {
		fmt.Println("ResolveTCPAddr failed:", err.Error())
		return "", err
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Println("Couldn't connect to server:", tcpAddr, err.Error())
		return "", err
	}
	defer conn.Close()

	// Sending data to the server
	_, err = fmt.Fprintf(conn, "%s\n%s\n%s\n", serverconn.ProfileId, expectedMAC, string(jsonData))
	if err != nil {
		fmt.Println("Error writing to the server:", err.Error())
		return "", err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading from the server:", err.Error())
		return "", err
	}

	if serverconn.Debug {
		fmt.Println("reply from server=", line)
	}
	return line, nil
}
