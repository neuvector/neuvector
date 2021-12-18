package common

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"syscall"
	"time"

	syslog "github.com/RackSec/srslog"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

const syslogFacility = syslog.LOG_LOCAL0
const notificationHeader = "notification"

type Syslogger struct {
	writer *syslog.Writer
	proto  string
	addr   string
	catSet utils.Set
	prio   syslog.Priority
	inJSON bool
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
		proto:  proto,
		addr:   fmt.Sprintf("%s:%d", server, cfg.SyslogPort),
		catSet: catSet,
		prio:   prio,
		inJSON: cfg.SyslogInJSON,
	}
}

func (s *Syslogger) Close() {
	if s.writer != nil {
		s.writer.Close()
	}
}

func (s *Syslogger) Send(elog interface{}, level, cat, header string) error {
	if !s.catSet.Contains(cat) {
		return nil
	}
	prio, ok := LevelToPrio(level)
	if !ok || prio > s.prio {
		return nil
	}

	if s.inJSON {
		if data, _ := json.Marshal(elog); len(data) > 2 {
			logText := fmt.Sprintf("{\"%s\": \"%s\", %s", notificationHeader, header, string(data[1:][:]))
			return s.send(logText, prio)
		}
	} else {
		if logText := struct2Text(elog); logText != "" {
			logText = fmt.Sprintf("%s=%s,%s", notificationHeader, header, logText)
			return s.send(logText, prio)
		}
	}

	return nil
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

				if tag := emt.Tag.Get("json"); tag != "" {
					logText = appendLogField(logText, tag, emf)
				}
			}
		} else {
			if tag := t.Tag.Get("json"); tag != "" {
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
	if wr, err := syslog.Dial(s.proto, s.addr, syslogFacility|prio, "neuvector"); err != nil {
		return err
	} else {
		wr.SetFormatter(syslog.RFC5424Formatter)
		s.writer = wr
		return s.sendWithLevel(text, prio)
	}
}

// --

const contentType = "application/json"

const webhookInfo = "Neuvector webhook is configured."
const requestTimeout = time.Duration(5 * time.Second)

type Webhook struct {
	url    string
	client *http.Client
}

func NewWebHook(url string) *Webhook {
	w := &Webhook{
		url: url,
		client: &http.Client{
			Timeout: requestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
	return w
}

func (w *Webhook) Validate() error {
	log.WithFields(log.Fields{"url": w.url}).Debug("")
	fields := make(map[string]string)
	fields["text"] = fmt.Sprintf("%s", webhookInfo)
	jsonValue, _ := json.Marshal(fields)

	return w.httpRequest(jsonValue)
}

func (w *Webhook) Notify(elog interface{}, target, level, category, cluster, title string) {
	log.WithFields(log.Fields{"title": title}).Debug()

	if logText := struct2Text(elog); logText != "" {
		var data []byte
		if target == api.WebhookTypeSlack {
			// Prefix category
			logText = fmt.Sprintf("%s=%s,%s", notificationHeader, category, logText)
			// Prefix category and title with styles
			logText = fmt.Sprintf("*%s: %s level*\n_%s_\n>>> %s", strings.Title(category), strings.ToUpper(LevelToString(level)), title, logText)
			fields := make(map[string]string)
			fields["text"] = logText
			fields["username"] = fmt.Sprintf("NeuVector - %s", cluster)
			data, _ = json.Marshal(fields)
		} else if target == api.WebhookTypeJSON {
			extra := fmt.Sprintf("{\"level\":\"%s\",\"cluster\":\"%s\",", strings.ToUpper(LevelToString(level)), cluster)
			data, _ = json.Marshal(elog)
			data = append([]byte(extra), data[1:]...)
		} else {
			msg := fmt.Sprintf("level=%s,cluster=%s,%s", strings.ToUpper(LevelToString(level)), cluster, logText)
			data = []byte(msg)
		}

		w.httpRequest(data)
	}
}

func (w *Webhook) httpRequest(data []byte) error {
	var err error
	var resp *http.Response
	retry := 0
	for retry < 3 {
		resp, err = w.client.Post(w.url, contentType, bytes.NewBuffer(data))
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
