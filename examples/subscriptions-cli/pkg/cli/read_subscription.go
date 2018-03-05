package cli

import (
	"encoding/json"
	"io/ioutil"

	api "github.com/capsule8/capsule8/api/v0"
)

// getSubscriptionsFromJSON takes a json blob and returns it
// marshalled as a slice of Subscription objects or an error
func getSubscipritionsFromJSON(blob []byte) (*api.Subscription, error) {
	subs := &api.Subscription{}

	err := json.Unmarshal(blob, &subs)
	if err != nil {
		return nil, err
	}

	return subs, nil
}

// getSubscriptionsFromFILE takes a JSON file name and returns its contents
// marshalled as a slice of Subscription objects or an error
func getSubscipritionsFromFile(filename string) (*api.Subscription, error) {
	blob, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return getSubscipritionsFromJSON(blob)
}
