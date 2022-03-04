package api

type Resource struct {
	ID      string            `json:"id,omitempty"`
	Type    string            `json:"type,omitempty"`
	Links   map[string]string `json:"links"`
	Actions map[string]string `json:"actions"`
}

type UserCondition struct {
	LastTransitionTime string `json:"lastTransitionTime,omitempty" yaml:"lastTransitionTime,omitempty"`
	LastUpdateTime     string `json:"lastUpdateTime,omitempty" yaml:"lastUpdateTime,omitempty"`
	Message            string `json:"message,omitempty" yaml:"message,omitempty"`
	Reason             string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Status             string `json:"status,omitempty" yaml:"status,omitempty"`
	Type               string `json:"type,omitempty" yaml:"type,omitempty"`
}

type OwnerReference struct {
	APIVersion         string `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	BlockOwnerDeletion *bool  `json:"blockOwnerDeletion,omitempty" yaml:"blockOwnerDeletion,omitempty"`
	Controller         *bool  `json:"controller,omitempty" yaml:"controller,omitempty"`
	Kind               string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Name               string `json:"name,omitempty" yaml:"name,omitempty"`
	UID                string `json:"uid,omitempty" yaml:"uid,omitempty"`
}

type User struct {
	Resource
	Annotations          map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Conditions           []UserCondition   `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	Created              string            `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID            string            `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	Description          string            `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled              *bool             `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Labels               map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Me                   bool              `json:"me,omitempty" yaml:"me,omitempty"`
	MustChangePassword   bool              `json:"mustChangePassword,omitempty" yaml:"mustChangePassword,omitempty"`
	Name                 string            `json:"name,omitempty" yaml:"name,omitempty"`
	OwnerReferences      []OwnerReference  `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	Password             string            `json:"password,omitempty" yaml:"password,omitempty"`
	PrincipalIDs         []string          `json:"principalIds,omitempty" yaml:"principalIds,omitempty"`
	Removed              string            `json:"removed,omitempty" yaml:"removed,omitempty"`
	State                string            `json:"state,omitempty" yaml:"state,omitempty"`
	Transitioning        string            `json:"transitioning,omitempty" yaml:"transitioning,omitempty"`
	TransitioningMessage string            `json:"transitioningMessage,omitempty" yaml:"transitioningMessage,omitempty"`
	UUID                 string            `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	Username             string            `json:"username,omitempty" yaml:"username,omitempty"`
}

type UserCollection struct {
	Collection
	Data []User `json:"data,omitempty"`
}

type Pagination struct {
	Marker   string `json:"marker,omitempty"`
	First    string `json:"first,omitempty"`
	Previous string `json:"previous,omitempty"`
	Next     string `json:"next,omitempty"`
	Last     string `json:"last,omitempty"`
	Limit    *int64 `json:"limit,omitempty"`
	Total    *int64 `json:"total,omitempty"`
	Partial  bool   `json:"partial,omitempty"`
}

type SortOrder string

type Sort struct {
	Name    string            `json:"name,omitempty"`
	Order   SortOrder         `json:"order,omitempty"`
	Reverse string            `json:"reverse,omitempty"`
	Links   map[string]string `json:"links,omitempty"`
}

type Collection struct {
	Type         string                 `json:"type,omitempty"`
	Links        map[string]string      `json:"links"`
	CreateTypes  map[string]string      `json:"createTypes,omitempty"`
	Actions      map[string]string      `json:"actions"`
	Pagination   *Pagination            `json:"pagination,omitempty"`
	Sort         *Sort                  `json:"sort,omitempty"`
	Filters      map[string][]Condition `json:"filters,omitempty"`
	ResourceType string                 `json:"resourceType"`
}

type ModifierType string

type Condition struct {
	Modifier ModifierType `json:"modifier,omitempty"`
	Value    interface{}  `json:"value,omitempty"`
}

type Principal struct {
	Resource
	Annotations     map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Created         string            `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID       string            `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	ExtraInfo       map[string]string `json:"extraInfo,omitempty" yaml:"extraInfo,omitempty"`
	Labels          map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	LoginName       string            `json:"loginName,omitempty" yaml:"loginName,omitempty"`
	Me              bool              `json:"me,omitempty" yaml:"me,omitempty"`
	MemberOf        bool              `json:"memberOf,omitempty" yaml:"memberOf,omitempty"`
	Name            string            `json:"name,omitempty" yaml:"name,omitempty"`
	OwnerReferences []OwnerReference  `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	PrincipalType   string            `json:"principalType,omitempty" yaml:"principalType,omitempty"`
	ProfilePicture  string            `json:"profilePicture,omitempty" yaml:"profilePicture,omitempty"`
	ProfileURL      string            `json:"profileURL,omitempty" yaml:"profileURL,omitempty"`
	Provider        string            `json:"provider,omitempty" yaml:"provider,omitempty"`
	Removed         string            `json:"removed,omitempty" yaml:"removed,omitempty"`
	UUID            string            `json:"uuid,omitempty" yaml:"uuid,omitempty"`
}

type PrincipalCollection struct {
	Collection
	Data []Principal `json:"data,omitempty"`
}
