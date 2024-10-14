package cache

/*
import (
	"crypto/tls"
	"encoding/json"
	"time"

	kafka "github.com/Shopify/sarama"
	log "github.com/sirupsen/logrus"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

type storeEvent struct {
	topic string
	key   string

	event   *share.Event
	threat  *share.Threat
	convers *share.Conversation
}

var storeEventChan chan *storeEvent = make(chan *storeEvent)

func createTlsConfiguration() (t *tls.Config) {
	cert, err := tls.LoadX509KeyPair(utils.SSLCertFile, utils.SSLKeyFile)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to load X509 keys")
	}

	t = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: false,
	}

	return t
}

func storeWorker(brokerList []string, config *kafka.Config) {
	var producer kafka.AsyncProducer
	var connected bool

	storeTicker := time.Tick(time.Second * time.Duration(5))
	storeErrorChan := make(chan *error)

	for {
		select {
		case <-storeErrorChan:
			producer.Close()
			connected = false
		case ev := <-storeEventChan:
			if connected {
				var value []byte
				switch ev.topic {
				case share.TopicEvent:
					log.WithFields(log.Fields{"event": ev.event.Name}).Debug("Write event log to store")
					value, _ = json.Marshal(*ev.event)
				case share.TopicThreat:
					log.WithFields(log.Fields{"threat": ev.threat.Name}).Debug("Write threat log to store")
					value, _ = json.Marshal(*ev.threat)
				case share.TopicConvers:
					log.WithFields(log.Fields{"bytes": ev.convers.Bytes}).Debug("Write conversation to store")
					value, _ = json.Marshal(*ev.convers)
				default:
					continue
				}
				producer.Input() <- &kafka.ProducerMessage{
					Topic: ev.topic,
					Key:   kafka.StringEncoder(ev.key),
					Value: kafka.ByteEncoder(value),
				}
			}
		case <-storeTicker:
			if !connected {
				var err error
				producer, err = kafka.NewAsyncProducer(brokerList, config)
				if err == nil {
					connected = true
					log.Debug("Connected to Kafka")

					go func() {
						pe := <-producer.Errors()
						log.Error(pe.Error())

						storeErrorChan <- &pe.Err
					}()
				}
			}
		}
	}
}

func startStoreThread(brokers []string) {
	log.WithFields(log.Fields{"brokers": brokers}).Debug("Kafka broker list")

	// kafka.Logger = log.StandardLogger()
	config := kafka.NewConfig()
	config.Producer.RequiredAcks = kafka.NoResponse
	config.Producer.Retry.Max = 0

	// TODO: enable TLS
	// tlsConfig := createTlsConfiguration()
	// if tlsConfig != nil {
	// 	config.Net.TLS.Config = tlsConfig
	// 	config.Net.TLS.Enable = true
	// }

	go storeWorker(brokers, config)
}
*/
