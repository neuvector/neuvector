package common

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
	syslog "github.com/neuvector/neuvector/share/utils/srslog"
)

const syslogFacility = syslog.LOG_LOCAL0
const notificationHeader = "notification"
const syslogTimeout = time.Second * 30
const syslogDialTimeout = time.Second * 30

type Syslogger struct {
	syslog     bool
	stdin      bool
	writer     *syslog.Writer
	proto      string
	addr       string
	catSet     utils.Set
	prio       syslog.Priority
	inJSON     bool
	serverCert string
}

func NewSyslogger(cfg *share.CLUSSyslogConfig) *Syslogger {
	var server, proto string
	if cfg.SyslogIP != nil {
		server = cfg.SyslogIP.String()
	} else {
		server = cfg.SyslogServer
	}
	if cfg.SyslogIPProto == syscall.IPPROTO_TCP {
		proto = "tcp"
	} else if cfg.SyslogIPProto == api.SyslogProtocolTCPTLS {
		proto = "tcp+tls"
	} else {
		proto = "udp"
	}
	prio, _ := LevelToPrio(cfg.SyslogLevel)
	catSet := utils.NewSet()
	for _, cat := range cfg.SyslogCategories {
		if cat == api.CategoryRuntime {
			catSet.Add(api.CategoryViolation)
			catSet.Add(api.CategoryThreat)
			catSet.Add(api.CategoryIncident)
		} else {
			catSet.Add(cat)
		}
	}
	return &Syslogger{
		syslog:     cfg.SyslogEnable,
		stdin:      cfg.OutputEventToLogs,
		proto:      proto,
		addr:       fmt.Sprintf("%s:%d", server, cfg.SyslogPort),
		catSet:     catSet,
		prio:       prio,
		inJSON:     cfg.SyslogInJSON,
		serverCert: cfg.SyslogServerCert,
	}
}

func (s *Syslogger) Close() {
	if s.writer != nil {
		s.writer.Close()
	}
}

func (s *Syslogger) Identifier() string {
	return s.proto + ":" + s.addr + ":" + s.serverCert // a string to identify its connection criteria
}

func (s *Syslogger) Send(elog interface{}, level, cat, header string) error {
	if !s.catSet.Contains(cat) {
		return nil
	}
	prio, ok := LevelToPrio(level)
	if !ok || prio > s.prio {
		return nil
	}

	var err error
	if s.inJSON {
		if data, _ := json.Marshal(elog); len(data) > 2 {
			logText := fmt.Sprintf("{\"%s\": \"%s\", %s", notificationHeader, header, string(data[1:][:]))
			if s.stdin {
				fmt.Println(logText)
			}
			if s.syslog {
				err = s.send(logText, prio)
			}
		}
	} else {
		if logText := struct2Text(elog); logText != "" {
			logText = fmt.Sprintf("%s=%s,%s", notificationHeader, header, logText)
			if s.stdin {
				fmt.Println(logText)
			}
			if s.syslog {
				err = s.send(logText, prio)
			}
		}
	}

	return err
}

func appendLogField(logText string, tag string, v reflect.Value) string {
	tokens := strings.Split(tag, ",")
	if len(tokens) > 1 && tokens[1] == "omitempty" {
		// Assume simple value, otherwise use deepequal()
		if v.Kind() == reflect.Slice {
			if v.Len() == 0 {
				return logText
			}
		} else if v.Kind() == reflect.Map {
			if v.Len() == 0 {
				return logText
			}
		} else {
			if isEmptyValue(v) {
				return logText
			}
		}
	}

	if logText == "" {
		return fmt.Sprintf("%s=%v", tokens[0], v)
	} else {
		return fmt.Sprintf("%s,%s=%v", logText, tokens[0], v)
	}
}

func struct2Text(elog interface{}) string {
	var logText string

	// check log pointer or struct
	v := reflect.ValueOf(elog).Elem()

	// get all the key and value
	for i := 0; i < v.NumField(); i++ {
		t := v.Type().Field(i)
		f := v.Field(i)

		if f.Kind() == reflect.Struct && t.Anonymous {
			for j := 0; j < f.NumField(); j++ {
				emt := f.Type().Field(j)
				emf := f.Field(j)

				if tag := emt.Tag.Get("json"); tag != "" && tag != "-" {
					logText = appendLogField(logText, tag, emf)
				}
			}
		} else {
			if tag := t.Tag.Get("json"); tag != "" && tag != "-" {
				logText = appendLogField(logText, tag, f)
			}
		}
	}
	return logText
}

func (s *Syslogger) sendWithLevel(text string, prio syslog.Priority) error {
	switch prio {
	case syslog.LOG_EMERG:
		return s.writer.Emerg(text)
	case syslog.LOG_ALERT:
		return s.writer.Alert(text)
	case syslog.LOG_CRIT:
		return s.writer.Crit(text)
	case syslog.LOG_ERR:
		return s.writer.Err(text)
	case syslog.LOG_WARNING:
		return s.writer.Warning(text)
	case syslog.LOG_NOTICE:
		return s.writer.Notice(text)
	case syslog.LOG_INFO:
		return s.writer.Info(text)
	case syslog.LOG_DEBUG:
		return s.writer.Debug(text)
	default:
		return s.writer.Debug(text)
	}
}

func (s *Syslogger) send(text string, prio syslog.Priority) error {
	if s.writer != nil {
		if err := s.sendWithLevel(text, prio); err == nil {
			return nil
		}

		s.Close()
	}
	if wr, err := s.makeDial(prio, syslogDialTimeout); err != nil {
		return err
	} else {
		wr.SetFormatter(syslog.RFC5424Formatter)
		wr.SetSendTimeout(syslogTimeout)
		s.writer = wr
		return s.sendWithLevel(text, prio)
	}
}

func (s *Syslogger) makeDial(prio syslog.Priority, timeout time.Duration) (*syslog.Writer, error) {
	if s.proto == "tcp+tls" {
		return syslog.DialWithTLSCert("tcp+tls", s.addr, timeout, syslogFacility|prio, "neuvector", []byte(s.serverCert))
	}

	return syslog.Dial(s.proto, s.addr, timeout, syslogFacility|prio, "neuvector")
}

// --

const webhookInfo = "Neuvector webhook is configured."
const requestTimeout = time.Duration(5 * time.Second)
const ctypeText = "text/plain; charset=us-ascii"
const ctypeJSON = "application/json"

type Webhook struct {
	url    string
	target string
}

func NewWebHook(url, target string) *Webhook {
	w := &Webhook{
		url:    url,
		target: target,
	}
	return w
}

func (w *Webhook) Notify(elog interface{}, level, category, cluster, title, comment string, proxy *share.CLUSProxy) {
	log.WithFields(log.Fields{"title": title}).Debug()

	if logText := struct2Text(elog); logText != "" {
		var data []byte
		var ctype string
		switch w.target {
		case api.WebhookTypeSlack:
			ctype = ctypeJSON
			// Prefix category
			logText = fmt.Sprintf("%s=%s,%s", notificationHeader, category, logText)
			// Prefix category and title with styles
			if comment != "" {
				logText = fmt.Sprintf("*%s: %s level, Comment: %s*\n_%s_\n>>> %s", strings.Title(category), strings.ToUpper(LevelToString(level)), comment, title, logText)
			} else {
				logText = fmt.Sprintf("*%s: %s level*\n_%s_\n>>> %s", strings.Title(category), strings.ToUpper(LevelToString(level)), title, logText)
			}

			fields := make(map[string]string)
			fields["text"] = logText
			fields["username"] = fmt.Sprintf("NeuVector - %s", cluster)
			data, _ = json.Marshal(fields)
		case api.WebhookTypeTeams:
			ctype = ctypeJSON
			fields := make(map[string]string)
			if comment != "" {
				fields["title"] = fmt.Sprintf("%s: %s level, Comment: %s", strings.Title(category), strings.ToUpper(LevelToString(level)), comment)
			} else {
				fields["title"] = fmt.Sprintf("%s: %s level", strings.Title(category), strings.ToUpper(LevelToString(level)))
			}

			fields["title"] = fmt.Sprintf("%s: %s level", strings.Title(category), strings.ToUpper(LevelToString(level)))
			logText = fmt.Sprintf("%s=%s,%s", notificationHeader, category, logText)
			fields["text"] = fmt.Sprintf("%s\n> %s", title, logText)
			data, _ = json.Marshal(fields)
		case api.WebhookTypeJSON:
			ctype = ctypeJSON
			var extra string
			if comment != "" {
				extra = fmt.Sprintf("{\"level\":\"%s\",\"cluster\":\"%s\",\"comment\":\"%s\",", strings.ToUpper(LevelToString(level)), cluster, comment)
			} else {
				extra = fmt.Sprintf("{\"level\":\"%s\",\"cluster\":\"%s\",", strings.ToUpper(LevelToString(level)), cluster)
			}

			data, _ = json.Marshal(elog)
			data = append([]byte(extra), data[1:]...)
		default:
			ctype = ctypeText
			var msg string
			if comment != "" {
				msg = fmt.Sprintf("level=%s,cluster=%s,comment=%s,%s", strings.ToUpper(LevelToString(level)), cluster, comment, logText)
			} else {
				msg = fmt.Sprintf("level=%s,cluster=%s,%s", strings.ToUpper(LevelToString(level)), cluster, logText)
			}
			data = []byte(msg)
		}

		w.httpRequest(data, ctype, proxy)
	}
}

func (w *Webhook) httpRequest(data []byte, ctype string, proxy *share.CLUSProxy) error {
	client := &http.Client{
		Timeout: requestTimeout,
	}

	var authHdr string
	if proxy != nil && proxy.Username != "" {
		authHdr = "Basic " + base64.StdEncoding.EncodeToString([]byte(proxy.Username+":"+proxy.Password))
	}

	if strings.HasPrefix(w.url, "https://") {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		if proxy != nil {
			transport.Proxy = func(r *http.Request) (*url.URL, error) {
				return url.Parse(proxy.URL)
			}
			if authHdr != "" {
				transport.ProxyConnectHeader = http.Header{}
				transport.ProxyConnectHeader.Add(
					"Proxy-Authorization", authHdr,
				)
			}
		}

		client.Transport = transport
	} else if strings.HasPrefix(w.url, "http://") {
		if proxy != nil {
			transport := &http.Transport{
				Proxy: func(r *http.Request) (*url.URL, error) {
					return url.Parse(proxy.URL)
				},
			}
			client.Transport = transport
		}
	}

	var err error
	var resp *http.Response
	retry := 0
	for retry < 3 {
		req, _ := http.NewRequest("POST", w.url, bytes.NewReader(data))
		// if authHdr is not empty, proxy must be enabled.
		if strings.HasPrefix(w.url, "http://") && authHdr != "" {
			req.Header.Add("Proxy-Authorization", authHdr)
		}
		req.Header.Set("Content-Type", ctype)

		resp, err = client.Do(req)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Webhook Send HTTP fail")
			return err
		} else {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			} else {
				err = fmt.Errorf("HTTP response: %s", resp.Status)
				if resp.StatusCode != http.StatusInternalServerError {
					log.WithFields(log.Fields{"error": err}).Error("Webhook server response error")
					return err
				}
			}
		}
		retry++
	}
	log.WithFields(log.Fields{"error": err}).Error("Webhook server internal error")
	return err
}
