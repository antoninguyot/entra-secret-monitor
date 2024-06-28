package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	gauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "entra_secret_monitor_expire_time_seconds",
	}, []string{"app_name", "secret_name"})
)

func main() {

	var refreshInterval time.Duration
	flag.DurationVar(&refreshInterval, "refresh-interval", time.Hour, "interval at which secrets are reloaded from Entra")
	flag.Parse()

	clientId := os.Getenv("CLIENT_ID")
	tenantId := os.Getenv("TENANT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	cred, err := azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, nil)

	if err != nil {
		fmt.Printf("Error creating credentials: %v\n", err)
	}

	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{})
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		return
	}

	go func() {
		for {
			// Set metrics here
			result, err := client.Applications().Get(context.Background(), nil)
			if err != nil {
				fmt.Printf("Error fetch applications: %v\n", err)
				return
			}

			for _, app := range result.GetValue() {
				log.Printf("--- Processing app %s (%s)", *app.GetDisplayName(), *app.GetId())
				for _, credential := range app.GetPasswordCredentials() {
					var credName string
					if credential.GetDisplayName() != nil {
						credName = *credential.GetDisplayName()
					} else {
						credName = "Unnamed credential"
					}
					fmt.Printf("Credential %s expires %s\n", credName, credential.GetEndDateTime())
					gauge.WithLabelValues(*app.GetDisplayName(), credName).Set(float64(credential.GetEndDateTime().Unix()))
				}
			}
			time.Sleep(refreshInterval * time.Second)
		}
	}()

	r := prometheus.NewRegistry()
	r.MustRegister(gauge)

	http.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
	http.ListenAndServe(":2112", nil)

}
