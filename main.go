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

var gauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "entra_secret_monitor_expire_time_seconds",
	Help: "Expiration time of Entra secrets in seconds since epoch",
}, []string{"app_name", "secret_name"})

func main() {
	var refreshInterval time.Duration
	flag.DurationVar(&refreshInterval, "refresh-interval", time.Hour, "interval at which secrets are reloaded from Entra")
	flag.Parse()

	clientId, tenantId, clientSecret := os.Getenv("CLIENT_ID"), os.Getenv("TENANT_ID"), os.Getenv("CLIENT_SECRET")
	if clientId == "" || tenantId == "" || clientSecret == "" {
		log.Fatal("CLIENT_ID, TENANT_ID, and CLIENT_SECRET environment variables must be set")
	}

	cred, err := azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, nil)
	if err != nil {
		log.Fatalf("Error creating credentials: %v", err)
	}

	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{})
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	go monitorSecrets(client, refreshInterval)

	r := prometheus.NewRegistry()
	r.MustRegister(gauge)

	http.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
	log.Fatal(http.ListenAndServe(":2112", nil))
}

func monitorSecrets(client *msgraphsdk.GraphServiceClient, refreshInterval time.Duration) {
	for {
		err := updateMetrics(client)
		if err != nil {
			log.Printf("Error updating metrics: %v", err)
		}
		time.Sleep(refreshInterval)
	}
}

func updateMetrics(client *msgraphsdk.GraphServiceClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := client.Applications().Get(ctx, nil)
	if err != nil {
		return fmt.Errorf("error fetching applications: %w", err)
	}

	for _, app := range result.GetValue() {
		appName := getStringValue(app.GetDisplayName(), "Unnamed app")
		appID := getStringValue(app.GetId(), "Unknown ID")

		log.Printf("Processing app %s (%s)", appName, appID)

		for _, credential := range app.GetPasswordCredentials() {
			credName := getStringValue(credential.GetDisplayName(), "Unnamed credential")
			expirationTime := credential.GetEndDateTime().Unix()

			log.Printf("Credential %s expires at %d", credName, expirationTime)
			gauge.WithLabelValues(appName, credName).Set(float64(expirationTime))
		}
	}

	return nil
}

func getStringValue(val *string, defaultVal string) string {
	if val != nil {
		return *val
	}
	return defaultVal
}
