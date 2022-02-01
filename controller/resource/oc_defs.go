package resource

import (
	metav1 "github.com/ericchiang/k8s/apis/meta/v1"
)

const (
	ocResImageStreams = "imagestreams"
	clusterOperators  = "clusteroperators"
)

type ocImageStreamTag struct {
	Name             string            `json:"name,omitempty"`
	Annotations      map[string]string `json:"annotations"`
	XXX_unrecognized []byte            `json:"-"`
}

type ocImageLookupPolicy struct {
	Local bool `json:"local,omitempty"`
}

type ocImageStreamSpec struct {
	Lookup           *ocImageLookupPolicy `json:"lookupPolicy,omitempty"`
	Tags             []*ocImageStreamTag  `json:"tags"`
	XXX_unrecognized []byte               `json:"-"`
}

type ocImageStreamStatusTagItem struct {
	Created          string `json:"created,omitempty"`
	Image            string `json:"image,omitempty"` // digest
	XXX_unrecognized []byte `json:"-"`
}

type ocImageStreamStatusTag struct {
	Tag              string                        `json:"tag"`
	Items            []*ocImageStreamStatusTagItem `json:"items"`
	XXX_unrecognized []byte                        `json:"-"`
}

type ocImageStreamStatus struct {
	Repo             string                    `json:"dockerImageRepository"`
	PublicRepo       string                    `json:"publicDockerImageRepository"`
	Tags             []*ocImageStreamStatusTag `json:"tags"`
	XXX_unrecognized []byte                    `json:"-"`
}

type ocImageStream struct {
	Metadata         *metav1.ObjectMeta   `json:"metadata"`
	Spec             *ocImageStreamSpec   `json:"spec"`
	Status           *ocImageStreamStatus `json:"status"`
	XXX_unrecognized []byte               `json:"-"`
}

func (m *ocImageStream) GetMetadata() *metav1.ObjectMeta {
	if m != nil {
		return m.Metadata
	}
	return nil
}

type ocImageStreamList struct {
	Metadata *metav1.ListMeta `json:"metadata"`
	Items    []*ocImageStream `json:"items"`
}

func (m *ocImageStreamList) GetMetadata() *metav1.ListMeta {
	if m != nil {
		return m.Metadata
	}
	return nil
}
