// hf-tlsmon project hf-tlsmon.go
package main

import (
	"bytes"
	"fmt"
	"github.com/juju/deputy"
	slack "github.com/monochromegane/slack-incoming-webhooks"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Allow logging of debug information (see: https://gist.github.com/a53mt/60c1002955e6d3096078).
const debug debugging = true // or flip to false
type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Printf("DEBUG  "+format, args...)
	}
}

// Holding information returned back from 'sslcheck' command.
type TLSHost struct {
	Host       string
	CommonName string
	Status     bool
	DaysLeft   int
	ExpireDate string
}

// Checks if a host is in alert state based on provided threshold.
func (h TLSHost) hasAlertState(threshold int) bool {
	if h.DaysLeft <= threshold {
		return true
	}
	return false
}

// An TLS host is in alert state if the TLS cert expires in less or equal 'ALERT_TRESHOLD' days.
const (
	ALERT_TRESHOLD              int    = 20
	SSLCHECK_TLSHOSTS_FILE_PATH string = "/etc/hf-tlsmon/tlshosts_to_check"
)

var (
	// The Slack client for sending messages.
	sc slack.Client
)

// Make sure we're operable.
func init() {
	// Check if required environment variable is set and not empty.
	siwhu := os.Getenv("SLACK_INCOMING_WEBHOOK_URL")
	if siwhu == "" {
		log.Fatalf("Error: Required environment variable SLACK_INCOMING_WEBHOOK_URL is empty or unset.\n")
	} else {
		sc = slack.Client{
			WebhookURL: siwhu,
		}
	}
	// Check if TLS hosts file later used by 'sslcheck' command is there.
	if _, err := os.Stat(SSLCHECK_TLSHOSTS_FILE_PATH); err != nil {
		log.Fatalf("Required sslcheck config file '/etc/hf-tlsmon/tlshosts_to_check' not found. Error: %s\n", err.Error())
	}

}

// Helper function.
func statToBool(status string) bool {
	if status == "Valid" {
		return true
	}
	return false
}

// Does never throws an error, but panics.
func daysLeftAsInt(daysLeft string) int {
	if res, err := strconv.Atoi(daysLeft); err != nil {
		panic(err)
	} else {
		return res
	}
}

// Using 'sslcheck' [1] command to fetch relevant information about TLS cert validity.
// [1] https://github.com/rossdylan/sslcheck
func checkTLSHosts() (string, error) {
	cmdStdoutPipeBuffer := bytes.NewBuffer(nil)
	d := deputy.Deputy{
		Errors: deputy.FromStderr,
		// Capture the cmd output into cmdStdOutPipeBuffer.
		StdoutLog: func(b []byte) {
			cmdStdoutPipeBuffer.WriteString(string(b) + "\n")
		},
		Timeout: time.Second * 30,
	}
	// It took me a long time to figure *this* *specific* *order* of args to pass to exec.Command:
	//     sh interpreter -> sh interpreter option '-c' -> cmd to exececute by shell interpreter as *one string*.
	cmd := exec.Command("/bin/sh", "-c", "/usr/local/bin/sslcheck -file "+SSLCHECK_TLSHOSTS_FILE_PATH)

	debug.Printf("(checkTLSHosts)  'cmd': %v\n", cmd.Args)
	if err := d.Run(cmd); err != nil {
		return "", fmt.Errorf("(checkTLSHosts) >>  Error executing cmd. Error: %s\n", err.Error())
	}
	debug.Printf("'%s'\n", cmdStdoutPipeBuffer.String())
	return cmdStdoutPipeBuffer.String(), nil
}

// Filters a given string slice 'input' and returns a new string slice.
// The returned string slice will contain only those elements x of 'input' where 'fCondFnc(x) == true'.
func filterStrSlc(input []string, fCondFnc func(elmToChk string) bool) []string {
	var res []string
	if len(input) == 0 {
		return res
	}
	for _, elm := range input {
		if fCondFnc(elm) {
			res = append(res, elm)
		}
	}
	return res
}

func main() {
	var sslcheckOutput string

	if checkedHosts, err := checkTLSHosts(); err != nil {
		log.Printf("Error while checking TLS hosts: %s\n", err.Error())
	} else {
		sslcheckOutput = checkedHosts
	}

	// Split into single lines
	inpLines := strings.Split(sslcheckOutput, "\n")

	// Filter out empty lines
	inpLines = filterStrSlc(inpLines, func(elm string) bool {
		if elm != "" {
			return true
		}
		return false
	})

	var tlsHosts []TLSHost

	// Split each line into relevant parts.
	for lNo, l := range inpLines {
		// Skip header line
		if lNo == 0 {
			continue
		}
		debug.Printf("  >>  CURRENT INPUT LINE  '%s'\n", l)

		spltdLineWS := strings.Split(l, "\t")

		for i, elm := range spltdLineWS {
			debug.Printf("Elm %d of spltdLineWS no %d is '%v'\n", i, lNo, elm)
		}

		// Remove all whitespace and empty-string elements from slice
		spltdLineWOutS := filterStrSlc(spltdLineWS,
			func(elm string) bool {
				elm = strings.TrimSpace(elm)
				if elm != "" {
					return true
				}
				return false
			})

		for i, elm := range spltdLineWOutS {
			debug.Printf("Elm %d of spltdLineW*O*S no %d is '%v'\n", i, lNo, elm)
		}
		tlsHosts = append(tlsHosts,
			TLSHost{
				Host:       spltdLineWOutS[0],
				CommonName: spltdLineWOutS[1],
				Status:     statToBool(spltdLineWOutS[2]),
				DaysLeft:   daysLeftAsInt(spltdLineWOutS[3]),
				ExpireDate: spltdLineWOutS[4],
			})
	}

	for _, t := range tlsHosts {
		debug.Printf("%#v\n", t)
	}

	log.Printf("***  TLS Hosts in ALTERT state (DaysLeft <= %d):  ***\n", ALERT_TRESHOLD)
	// Collect attachments before sending message.
	var atchmnts []*slack.Attachment
	for _, t := range tlsHosts {
		if t.hasAlertState(ALERT_TRESHOLD) {
			log.Printf("Host '%s' is in ALERT state - only %d days left before TLS cert expires.\n", t.Host, t.DaysLeft)
			atchmnts = append(atchmnts, creatSlackMsgAtchmnt(&t, len(tlsHosts)))
		}
	}
	// Send actual message containing all the hosts in alert state as attachments.
	if err := sc.Post(&slack.Payload{
		Text:        fmt.Sprintf("<!group> *Following TLS/SSL host(s) is/are in ALERT state (%d hosts checked):*", len(tlsHosts)),
		Attachments: atchmnts,
	}); err != nil {
		log.Printf("Error sending message to Slack incoming webhook: %s\n", err.Error())
		os.Exit(1)
	}
	log.Println("Successfully send message to Slack incoming webhook.")

} // main

// Creating the attachments for the Slack incoming webhook payload.
func creatSlackMsgAtchmnt(tlsHost *TLSHost, numChkdHosts int) *slack.Attachment {
	atchmnt := slack.Attachment{
		Title: "TLS/SSL cert expiration alert.",
		Color: "danger",
		Fields: []*slack.Field{
			&slack.Field{
				Title: "TLS Host",
				Value: tlsHost.Host,
				Short: true,
			},
			&slack.Field{
				Title: "Days left",
				Value: fmt.Sprintf("%d", tlsHost.DaysLeft),
				Short: true,
			}},
	}
	return &atchmnt
}
