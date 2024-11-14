package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/juju/ratelimit"
	"github.com/miekg/dns"
)

type Device struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

type Resolver struct {
	Nameserver string
	Limiter    *ratelimit.Bucket
}

type Response struct {
	Domain        string
	Nameserver    string
	ResponseType  string
	Response      string
	CanonicalName string
}

func queryDomain(device, domain string, resolver Resolver, wg *sync.WaitGroup, ch chan<- Response) {
	defer wg.Done()

	limiter := resolver.Limiter
	limiter.Wait(1)

	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)

	r, _, err := client.Exchange(msg, resolver.Nameserver)
	if err != nil {
		ch <- Response{Domain: domain, Nameserver: resolver.Nameserver, ResponseType: "Query error", Response: err.Error()}
		return
	}

	if len(r.Answer) == 0 {
		ch <- Response{Domain: domain, Nameserver: resolver.Nameserver, ResponseType: "No AAAA answer received", Response: "No AAAA answer received"}
		return
	}

	var ipv6Addresses []string
	var canonicalName string
	for _, ans := range r.Answer {
		switch t := ans.(type) {
		case *dns.AAAA:
			ipv6Addresses = append(ipv6Addresses, t.AAAA.String())
		case *dns.CNAME:
			canonicalName = t.Target
		}
	}

	ch <- Response{Domain: domain, Nameserver: resolver.Nameserver, ResponseType: "no error AAAA response", Response: fmt.Sprintf("%s", ipv6Addresses), CanonicalName: canonicalName}
}

func main() {
	file, err := os.Open("../dest-analysis/output/all_domain_list_all.json")
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		return
	}
	defer file.Close()

	var devices map[string]Device
	if err := json.NewDecoder(file).Decode(&devices); err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	// Filter devices
	filteredDevices := make(map[string]Device)
	for k, v := range devices {
		filteredDevices[k] = v
	}
	devices = filteredDevices

	resolvers := []Resolver{
		{Nameserver: "8.8.8.8:53", Limiter: ratelimit.NewBucketWithRate(5, 1)},
		{Nameserver: "[2001:4860:4860::8888]:53", Limiter: ratelimit.NewBucketWithRate(5, 1)},
	}

	var wg sync.WaitGroup
	responseChannel := make(chan Response, len(devices)*len(resolvers))

	for deviceName, device := range devices {
		for _, domain := range device.Domains {
			for _, resolver := range resolvers {
				wg.Add(1)
				go queryDomain(deviceName, domain, resolver, &wg, responseChannel)
			}
		}
	}

	wg.Wait()
	close(responseChannel)

	responses := make(map[string][]Response)
	for response := range responseChannel {
		responses[response.Domain] = append(responses[response.Domain], response)
	}

	for device, responseList := range responses {
		outputFile, err := os.Create(fmt.Sprintf("output/%s.csv", device))
		if err != nil {
			fmt.Println("Error creating CSV file:", err)
			continue
		}
		defer outputFile.Close()

		writer := csv.NewWriter(outputFile)
		defer writer.Flush()

		writer.Write([]string{"Domain", "Resolver", "Response Type", "Response", "Canonical Name"})
		for _, resp := range responseList {
			writer.Write([]string{resp.Domain, resp.Nameserver, resp.ResponseType, resp.Response, resp.CanonicalName})
		}
	}
}