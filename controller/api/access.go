package api

import (
	"encoding/json"

	"github.com/neuvector/neuvector/share"
)

func (o *RESTLicenseInfo) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *RESTSystemStats) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *RESTScanStatus) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *RESTConversationEndpoint) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	if o.Domain == "" {
		return nil, nil
	} else {
		return []string{o.Domain}, nil
	}
}

func (o *RESTConversation) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	from, _ := o.From.GetDomain(f)
	to, _ := o.To.GetDomain(f)
	if from == nil && to != nil {
		from = []string{""}
	} else if from != nil && to == nil {
		to = []string{""}
	}
	return from, to
}

// NOTE: This is a special case. Only read is authorized, but there is no data structure associated
//
//	with the write action. We use this object to authorize again.
func (o *RESTWorkloadBrief) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	return []string{o.Domain}, nil
}

func (o *Event) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	if o.WorkloadDomain != "" {
		return []string{o.WorkloadDomain}, nil
	} else if o.UserRoles != nil {
		list := make([]string, 0, len(o.UserRoles))
		for domain := range o.UserRoles {
			list = append(list, domain)
		}
		return list, nil
	} else if o.User != "" {
		if f != nil {
			if user := f(o.User); user != nil {
				d1, d2 := user.GetDomain(nil)
				// Because events are read-only, there is no need to adjust when d1 is nil but d2 is not nil
				return d1, d2
			}
		}
	}
	return nil, nil
}

func (o *RESTSystemUsageReport) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *Threat) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	return []string{o.ClientWLDomain}, []string{o.ServerWLDomain}
}

func (o *Incident) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	return []string{o.WorkloadDomain}, nil
}

func (o *Violation) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	return []string{o.ClientDomain}, []string{o.ServerDomain}
}

func (o *Audit) GetDomain(f share.GetAccessObjectFunc) ([]string, []string) {
	return []string{o.WorkloadDomain}, nil
}

// temporarily revert critical cve logic
func (c VulAssetCountDist) MarshalJSON() ([]byte, error) {
	type Alias VulAssetCountDist
	alias := struct {
		Alias
		Critical *int `json:"critical,omitempty"`
	}{
		Alias: (Alias)(c),
	}
	if c.Critical >= 0 {
		alias.Critical = &c.Critical
	}
	return json.Marshal(alias)
}

func (c AssetCVECount) MarshalJSON() ([]byte, error) {
	type Alias AssetCVECount
	alias := struct {
		Alias
		Critical *int `json:"critical,omitempty"`
	}{
		Alias: (Alias)(c),
	}
	if c.Critical >= 0 {
		alias.Critical = &c.Critical
	}
	return json.Marshal(alias)
}

func (c RESTImageAssetViewV2) MarshalJSON() ([]byte, error) {
	type Alias RESTImageAssetViewV2
	alias := struct {
		Alias
		Critical *int `json:"critical,omitempty"`
	}{
		Alias: (Alias)(c),
	}
	if c.Critical >= 0 {
		alias.Critical = &c.Critical
	}
	return json.Marshal(alias)
}
