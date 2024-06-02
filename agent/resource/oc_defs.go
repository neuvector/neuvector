// [20220809] this is a simplified version of controller/resource/oc_defs.go
package resource

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              *ocImageStreamSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status            *ocImageStreamStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
	XXX_unrecognized  []byte               `json:"-"`
}

type ocImageStreamList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []ocImageStream `json:"items" protobuf:"bytes,2,rep,name=items"`
}
