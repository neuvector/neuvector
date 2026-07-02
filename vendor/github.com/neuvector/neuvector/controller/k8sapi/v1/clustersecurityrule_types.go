package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:object:root=true
// +kubebuilder:resource:singular="nvclustersecurityrule",path="nvclustersecurityrules",scope="Cluster"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NvClusterSecurityRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              NvSecurityRuleSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NvClusterSecurityRuleList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvClusterSecurityRule `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte                  `json:"-"`
}
