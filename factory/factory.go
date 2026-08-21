// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

/*
 * SMF Configuration Factory
 */

package factory

import (
	"fmt"
	"net/url"
	"os"
	"sync"

	"github.com/omec-project/smf/logger"
	"go.yaml.in/yaml/v4"
)

var (
	SmfConfig         Config
	UERoutingConfig   RoutingConfig
	SmfConfigSyncLock sync.Mutex
)

// InitConfigFactory gets the NrfConfig and subscribes the config pod.
// This observes the GRPC client availability and connection status in a loop.
// When the GRPC server pod is restarted, GRPC connection status stuck in idle.
// If GRPC client does not exist, creates it. If client exists but GRPC connectivity is not ready,
// then it closes the existing client start a new client.
func InitConfigFactory(f string) error {
	content, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	SmfConfig = Config{}

	if err = yaml.Unmarshal(content, &SmfConfig); err != nil {
		return err
	}

	// The lenient decode above is upstream's and stays lenient — this fork must keep starting
	// when upstream adds a key it does not model. The LI block is held to a stricter standard,
	// on its own, because a key dropped there lands on a default that fails unsafely and says
	// nothing: see strictLiBlock.
	//
	// **Recorded, not returned.** Returning it failed the whole configuration load, which stops
	// the SMF: PFCP, the service-based interface, registration with the network, every
	// subscriber's sessions — over a typo in an optional subsystem. That is the outage this
	// fork's own `service/init.go` comment describes and refuses to cause for an unreadable
	// keepalive window, arrived at one frame earlier and in another package. It is also the
	// louder half of undetectability: a network function that will not start is visible to every
	// operator and peer, where a log line is visible only to whoever reads logs.
	//
	// The refusal is carried to the LI subsystem instead, which is the only party that can act
	// on it — it declines to intercept and reports the invalid configuration to the ADMF, at a
	// point where the reporting channel exists. See LiBlockError.
	liBlockErr = strictLiBlock(content)

	if SmfConfig.Configuration.KafkaInfo.EnableKafka == nil {
		enableKafka := true
		SmfConfig.Configuration.KafkaInfo.EnableKafka = &enableKafka
	}

	if SmfConfig.Configuration.WebuiUri == "" {
		SmfConfig.Configuration.WebuiUri = "http://webui:5001"
		logger.CfgLog.Infof("webuiUri not set in configuration file. Using %v", SmfConfig.Configuration.WebuiUri)
		return nil
	}
	err = validateWebuiUri(SmfConfig.Configuration.WebuiUri)
	return err
}

func validateWebuiUri(uri string) error {
	parsedUrl, err := url.ParseRequestURI(uri)
	if err != nil {
		return err
	}
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return fmt.Errorf("unsupported scheme for webuiUri: %s", parsedUrl.Scheme)
	}
	if parsedUrl.Hostname() == "" {
		return fmt.Errorf("missing host in webuiUri")
	}
	return nil
}

func InitRoutingConfigFactory(f string) error {
	if content, err := os.ReadFile(f); err != nil {
		return err
	} else {
		UERoutingConfig = RoutingConfig{}

		if yamlErr := yaml.Unmarshal(content, &UERoutingConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func CheckConfigVersion() error {
	currentVersion := SmfConfig.GetVersion()

	if currentVersion != SMF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("SMF config version is [%s], but expected is [%s]",
			currentVersion, SMF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("SMF config version [%s]", currentVersion)

	currentVersion = UERoutingConfig.GetVersion()

	if currentVersion != UE_ROUTING_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("UE-Routing config version is [%s], but expected is [%s]",
			currentVersion, UE_ROUTING_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("UE-Routing config version [%s]", currentVersion)

	return nil
}
