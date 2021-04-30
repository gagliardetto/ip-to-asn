package iptoasn

import (
	"errors"
	"log"
	"os"
	"time"

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/services/sources"
	"github.com/gagliardetto/futures"
)

var Timeout = time.Second * 10

var (
	DNSServers = []string{
		"1.1.1.1:53",     // Cloudflare
		"8.8.8.8:53",     // Google
		"64.6.64.6:53",   // Verisign
		"74.82.42.42:53", // Hurricane Electric
		"1.0.0.1:53",     // Cloudflare Secondary
		"8.8.4.4:53",     // Google Secondary
		"9.9.9.10:53",    // Quad9 Secondary
		"64.6.65.6:53",   // Verisign Secondary
		"77.88.8.1:53",   // Yandex.DNS Secondary
	}
)
var (
	resolverPool = resolvers.SetupResolverPool(
		DNSServers,
		false,
		false,
	)
)

type ASNInfoGetter struct {
	bus *eventbus.EventBus
	ft  futures.Futures
}

func NewASNInfoGetter() *ASNInfoGetter {
	conf := &config.Config{}
	conf.Active = true
	conf.Log = log.New(os.Stderr, "ASNInfoGetter-", log.Lmicroseconds)
	bus := eventbus.NewEventBus()
	addrService := services.NewAddressService(conf, bus, resolverPool)
	addrService.Start()

	cym := sources.NewTeamCymru(conf, bus, resolverPool)
	go cym.Start()
	ft := futures.New()

	bus.Subscribe(requests.NewASNTopic, func(asnInfo *requests.ASNRequest) {
		ip := asnInfo.Address
		ft.Answer(ip, asnInfo, nil)
	})

	getter := &ASNInfoGetter{
		bus: bus,
		ft:  ft,
	}

	return getter
}
func (gttr *ASNInfoGetter) GetASNInfo(ip string) (*requests.ASNRequest, error) {

	ans, err := gttr.ft.AskWithTimeoutAndPostSubscriptionCallback(
		ip,
		Timeout,
		func() {
			gttr.bus.Publish(requests.IPToASNTopic, &requests.ASNRequest{
				Address: ip,
			})
		},
	)
	if err != nil {
		return nil, err
	}

	if ans == nil {
		return nil, errors.New("not found")
	}

	return ans.(*requests.ASNRequest), nil
}
