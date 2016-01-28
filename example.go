package main

import (
	"net/http"
	"bufio"
	"bytes"
	"fmt"
	"github.com/elico/go-shadowd"
	"encoding/json"
)

func main() {

newReq :=`POST /test/otp/example.php HTTP/1.1
Host: 192.168.10.194


`
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer([]byte(newReq))))
		if err != nil {
			panic(err)
		}
		req.RemoteAddr = "192.168.10.131:5000"

		shadowServer := shadowd.ShadowdConn { ServerAddr:"192.168.10.194:9115",
						ReadBody:false, 
						ProfileId: "2", 
						Logfile: "", 
						Debug: false,
						ProfileKey: "102030",
						}
		res, err := shadowServer.SendToShadowd(req)
		newmap := make(map[string]interface{})
		err = json.Unmarshal([]byte(res), &newmap)
		if err != nil {
			panic(err)
		}
		switch int(newmap["status"].(float64)) {
		case shadowd.STATUS_OK:
			fmt.Println("Request reported, OK")
		case shadowd.STATUS_BAD_REQUEST:
		
		case shadowd.STATUS_BAD_SIGNATURE:
		
		case shadowd.STATUS_BAD_JSON:
		
		case shadowd.STATUS_ATTACK:
			fmt.Println("This is an attack, needs to take action!")
		case shadowd.STATUS_CRITICAL_ATTACK:
			fmt.Println("This is an attack, needs to take action!")
		default:
			fmt.Println("Something werid happen, response code => ", int(newmap["status"].(float64)) )
		}
}
