package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"net"
	"strconv"
)

// nagios exit codes
const (
	OK = iota
	WARNING
	CRITICAL
	UNKNOWN
)

// export NCG2=debug
const DEBUG = "NCG2"

// license information
const (
        author = "Robin Bourne, forked from Antonino Catinello work"
        license = "BSD"
        year = "2016"
        copyright = "\u00A9"
)


var (
	// command line arguments
	link *string
	user *string
	pass *string
	version *bool
	// using ssl to avoid name conflict with tls
	ssl *bool
	// env debugging variable
	debug string
	// performance data
	pdata string
	// version value
	id string
	// collector warn threshold
	collectorWT *int
	// collector warn threshold
	collectorCT *int
	// expected number of collectors
	expectedCollectors *int
)

// handle performance data output
func perf(elapsed, total, inputs, tput, index, collectors, failureCollectors, offlineCollectors  float64) {
	pdata = fmt.Sprintf("time=%f;;;; total=%.f;;;; sources=%.f;;;; throughput=%.f;;;; index_failures=%.f;;;; collectors=%.f;;;; collector_failure=%.f;;;; collector_offline=%.f;;;;", elapsed, total, inputs, tput, index, collectors, failureCollectors, offlineCollectors)
}

// handle args
func init() {
	link = flag.String("l", "http://localhost:12900", "Graylog2 API URL - REQUIRED")
	user = flag.String("u", "", "API username - REQUIRED")
	pass = flag.String("p", "", "API password - REQUIRED")
	ssl = flag.Bool("insecure", false, "Accept insecure SSL/TLS certificates.")
	version = flag.Bool("version", false, "Display version and license information.")
	expectedCollectors = flag.Int("ex", 0, "Expected Number of Collectors")
	collectorWT = flag.Int("wt", 1, "Collection Warning Threshold")
	collectorCT = flag.Int("ct", 2, "Collection Critical Threshold")

	debug = os.Getenv(DEBUG)
	perf(0, 0, 0, 0, 0, 0, 0, 0)
}

// return nagios codes on quit
func quit(status int, message string, err error) {
	var ev string

	switch status {
	case OK:
		ev = "OK"
	case WARNING:
		ev = "WARNING"
	case CRITICAL:
		ev = "CRITICAL"
	case UNKNOWN:
		ev = "UNKNOWN"
	}

	// if debugging is enabled
	// print errors
	if len(debug) != 0 {
		fmt.Println(err)
	}

	fmt.Printf("%s - %s|%s\n", ev, message, pdata)
	os.Exit(status)
}

// parse link
func parse(link *string) string {
	l, err := url.Parse(*link)
	if err != nil {
		quit(UNKNOWN, "Can not parse given URL.", err)
	}
	host, port, _ := net.SplitHostPort(l.Host)

	if len(host) == 0 {
		quit(UNKNOWN, "Hostname is missing.", err)
	}

	if _, err := strconv.Atoi(port); err != nil {
		quit(UNKNOWN, "Port is not a number.", err)
	}

	if !strings.HasPrefix(l.Scheme, "HTTP") && !strings.HasPrefix(l.Scheme, "http") {
		quit(UNKNOWN, "Only HTTP/S protocols are supported.", err)
	}

	s := l.String()
	//check for trailing slash
	if s[len(s)-1:] == "/" {
		s = s[0:len(s)-1]
	}

	return s
}

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Version: %v License: %v %v %v %v\n", id, license, copyright, year, author)
		os.Exit(3)
	}

	if len(*user) == 0 || len(*pass) == 0 {
		flag.PrintDefaults()
		os.Exit(3)
	}

	c := parse(link)
	start := time.Now()

	system := query(c+"/system", *user, *pass)
	if system["is_processing"].(bool) != true {
		quit(CRITICAL, "Service is not processing", nil)
	}
	if strings.Compare(system["lifecycle"].(string), "running") != 0 {
		quit(WARNING, fmt.Sprintf("lifecycle: %v", system["lifecycle"].(string)), nil)
	}
	if strings.Compare(system["lb_status"].(string), "alive") != 0 {
		quit(WARNING, fmt.Sprintf("lb_status: %v", system["lb_status"].(string)), nil)
	}

	index := query(c+"/system/indexer/failures", *user, *pass)
	tput := query(c+"/system/throughput", *user, *pass)
	inputs := query(c+"/system/inputs", *user, *pass)
	total := query(c+"/count/total", *user, *pass)

	collectors := query(c+"/plugins/org.graylog.plugins.collector/collectors", *user, *pass)

	failures := 0
	offline := 0
	collectorCount:=0

	for index := range collectors["collectors"].([]interface {}) {
		collectorCount++
		element := collectors["collectors"].([]interface{})[index].(map[string]interface{})

		if !element["active"].(bool) {
			offline++
		} else {
			status := element["node_details"].(map[string]interface{})["status"].(map[string]interface{})["status"].(float64)
			// 0= Running, 1=Unknown, 2=Failing, default=Unknown
			if (status > 0) {
				failures++;
			}
		}
	}

	elapsed := time.Since(start)

	perf(elapsed.Seconds(), total["events"].(float64), inputs["total"].(float64), tput["throughput"].(float64), index["total"].(float64), float64(collectorCount), float64(failures), float64(offline))

	if (failures + offline >= *collectorCT) {
		if (failures > 0 && offline > 0) {
			quit(CRITICAL, fmt.Sprintf("%d collectors are failing and %d are inactive", failures, offline), nil)
		} else if (failures > 0) {
			quit(CRITICAL, fmt.Sprintf("%d collectors are failing", failures), nil)
		} else {
			quit(CRITICAL, fmt.Sprintf("%d collectors are inactive", offline), nil)
		}
	} else if (failures + offline >= *collectorWT) {
		if (failures > 0 && offline > 0) {
			quit(WARNING, fmt.Sprintf("%d collectors are failing and %d are inactive", failures, offline), nil)
		} else if (failures > 0) {
			quit(WARNING, fmt.Sprintf("%d collectors are failing", failures), nil)
		} else {
			quit(WARNING, fmt.Sprintf("%d collectors are inactive", offline), nil)
		}
	}

	if (*expectedCollectors > 0 && *expectedCollectors != collectorCount) {
		quit(CRITICAL, fmt.Sprintf("Expecting %d collectors but %d reported in", *expectedCollectors, collectorCount), nil)
	}

	quit(OK, fmt.Sprintf("Service is running!\n%.f total events processed\n%.f index failures\n%.f throughput\n%.f sources\n%.f collectors detected\n%.f collectors offline\n%.f collectors failing\nCheck took %v",
		total["events"].(float64), index["total"].(float64), tput["throughput"].(float64), inputs["total"].(float64), float64(collectorCount), float64(offline), float64(failures), elapsed), nil)
}

// call Graylog2 HTTP API
func query(target string, user string, pass string) map[string]interface{} {
	var client *http.Client
	var data map[string]interface{}

	if *ssl {
		tp := &http.Transport{
			// keep this necessary evil for internal servers with custom certs?
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client = &http.Client{Transport: tp}
	} else {
		client = &http.Client{}
	}

	req, err := http.NewRequest("GET", target, nil)
	req.SetBasicAuth(user, pass)

	res, err := client.Do(req)
	if err != nil {
		quit(CRITICAL, "Can not connect to Graylog2 API", err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		quit(CRITICAL, "No response received from Graylog2 API", err)
	}

	if len(debug) != 0 {
		fmt.Println(string(body))
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		quit(UNKNOWN, "Can not parse JSON from Graylog2 API", err)
	}

	if res.StatusCode != 200 {
		quit(CRITICAL, fmt.Sprintf("Graylog2 API replied with HTTP code %v", res.StatusCode), err)
	}

	return data
}
