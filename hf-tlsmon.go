// hf-tlsmon project hf-tlsmon.go
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/juju/deputy"
	slack "github.com/monochromegane/slack-incoming-webhooks"
	"github.com/peterbourgon/g2s"
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

const (
	SSLCHECK_TLSHOSTS_FILE_PATH string = "/etc/hf-tlsmon/tlshosts_to_check"
	STATSD_METRIC_NAME          string = "tlsmon.alive"
)

var (
	// The Slack client for sending messages.
	sc slack.Client
	// An TLS host is in alert state if the TLS cert expires in less or equal 'alertThreshold' days.
	certAlertThreshold int
	// The StatsD client for publishing metrics.
	statsd *g2s.Statsd = nil
	// The "special word" in the text message which get's handled in a predefined way by the Slack client.
	// Default value is '<!group>' because it's universally understood for paid and unpaid Slack teams.
	// Reference: https://api.slack.com/docs/message-formatting#variables
	txtMsgSpecialWord string = "group"
)

// Make sure we're operable.
func init() {
	// Check if required environment variables are set and not empty.
	siwhu := os.Getenv("SLACK_INCOMING_WEBHOOK_URL")
	if siwhu == "" {
		log.Fatalf("Error: Required environment variable SLACK_INCOMING_WEBHOOK_URL is empty or unset.\n")
	} else {
		sc = slack.Client{
			WebhookURL: siwhu,
		}
	}
	cat := os.Getenv("CERT_ALERT_THRESHOLD")
	if cat == "" {
		log.Fatalf("Error: Required environment variable CERT_ALERT_THRESHOLD is empty or unset.\n")
	} else {
		// Try to parse provided threshold string as integer.
		if catInt, err := strconv.Atoi(cat); err != nil {
			log.Fatalf("Error: Unable to parse given CERT_ALERT_THRESHOLD '%s' as integer value: %s\n", cat, err.Error())
		} else {
			certAlertThreshold = catInt
		}
	}
	sda := os.Getenv("STATSD_ADDRESS")
	if sda == "" {
		log.Printf("Warning: Optional environment variable STATSD_ADDRESS is empty or unset. Not sending alive metric.\n")
	} else {
		s, err := g2s.Dial("udp", sda)
		if err != nil {
			log.Printf("WARNING: Unable to connect to StatsD host '%s'; error: %s. *Not* publishing metrics but running anyway.\n", sda, err.Error())
		} else {
			// Bind new StatsD client to global var.
			statsd = s
		}
	}
	tmsw := os.Getenv("TEXT_MSG_SPECIAL_WORD")
	if tmsw == "" {
		log.Printf("Warning: Optional environment variable TEXT_MSG_SPECIAL_WORD is empty or unset. Falling back to '<!group>'.\n")
	} else {
		txtMsgSpecialWord = tmsw
	}
	// Check if TLS hosts file later used by 'sslcheck' command is there.
	if _, err := os.Stat(SSLCHECK_TLSHOSTS_FILE_PATH); err != nil {
		log.Fatalf("Required sslcheck config file '/etc/hf-tlsmon/tlshosts_to_check' not found. Error: %s\n", err.Error())
	}
}

// Helper function for publishing counter metrics to StatsD.
func incrStatsDCounterBy1(statsd *g2s.Statsd, counterName string) {
	// Only do something if we have a valid client.
	if statsd != nil {
		statsd.Counter(1.0, counterName, 1)
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
		Timeout: time.Second * 180,
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

	log.Printf("***  TLS Hosts in ALTERT state (DaysLeft <= %d):  ***\n", certAlertThreshold)
	// Collect attachments before sending message.
	var atchmnts []*slack.Attachment
	for _, t := range tlsHosts {
		if t.hasAlertState(certAlertThreshold) {
			log.Printf("Host '%s' is in ALERT state - only %d days left before TLS cert expires.\n", t.Host, t.DaysLeft)
			atchmnts = append(atchmnts, creatSlackMsgAtchmnt(&t, len(tlsHosts)))
		}
	}
	// Send actual message containing all the hosts in alert state as attachments.
	if len(atchmnts) > 0 {
		txtMsgToSend := fmt.Sprintf("<!%s> *Following TLS/SSL host(s) is/are in ALERT state (%d hosts checked):*", txtMsgSpecialWord, len(tlsHosts))
		debug.Printf("'txtMsgToSend': '%s'\n", txtMsgToSend)
		if err := sc.Post(&slack.Payload{
			Text:        txtMsgToSend,
			Attachments: atchmnts,
		}); err != nil {
			log.Printf("Error sending message to Slack incoming webhook: %s\n", err.Error())
			os.Exit(1)
		}
		log.Println("Successfully send message to Slack incoming webhook.")
	}
	// Indicate that a TLS hosts check took place and we are alive.
	incrStatsDCounterBy1(statsd, STATSD_METRIC_NAME)

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
