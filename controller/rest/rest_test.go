package rest

import (
	"net/http"
	"testing"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"
)

type Star struct {
	Name    string   `json:"name,omitempty"`
	Size    int      `json:"size"`
	Mass    int32    `json:"mass"`
	Gravity float32  `json:"gravity"`
	Planets []string `json:"planets"`
	Visible bool     `json:"visible"`
}

var sun Star = Star{
	Name:    "Sun",
	Size:    109,
	Mass:    1,
	Gravity: 27.94,
	Planets: []string{"Mercury", "Venus", "Earth"},
	Visible: true,
}

var sirius Star = Star{
	Name:    "Sirius",
	Size:    185,
	Mass:    2,
	Gravity: 21379.62,
	Planets: []string{"A CMa A", "A CMa B"},
	Visible: true,
}

var gliese Star = Star{
	Name:    "Gliese",
	Size:    34,
	Mass:    1,
	Gravity: 13484.66,
	Planets: []string{"876 d", "876 c", "876 b"},
	Visible: false,
}

func TestFilterStrEq(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "name",
			op:    api.OPeq,
			value: "Sun",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Should be aceepted.")
	}
}

func TestFilterStrEqNegtive(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "name",
			op:    api.OPeq,
			value: "Sirius",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if rf.Filter(&sun) {
		t.Fatalf("Should be filtered.")
	}
}

func TestFilterStrNeq(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "name",
			op:    api.OPneq,
			value: "Sirius",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Should be accepted.")
	}
}

func TestFilterStrIn(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "name",
			op:    api.OPin,
			value: "Su",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Should be accepted.")
	}
}

func TestFilterStrGte(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "name",
			op:    api.OPgte,
			value: "Orion",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Should be accepted.")
	}
}

func TestFilterIntLt(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "size",
			op:    api.OPlt,
			value: "200",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Should be accepted.")
	}
}

func TestFilterFloatNeg(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "gravity",
			op:    api.OPlte,
			value: "18.5",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if rf.Filter(&sun) {
		t.Fatalf("Should be filtered.")
	}
}

func TestFilterBoolLte(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "visible",
			op:    api.OPlte,
			value: "True",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Should be accepted.")
	}
}

func TestFilterBoolInvalidValue(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "visible",
			op:    api.OPeq,
			value: "invalid",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Ignore unparseable value. Should be accepted.")
	}
}

func TestFilterArrayNotSupport(t *testing.T) {
	log.SetLevel(log.FatalLevel)

	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "planets",
			op:    api.OPeq,
			value: "Earth",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Ignore unsupported type. Should be accepted.")
	}

	log.SetLevel(log.DebugLevel)
}

func TestFilterFieldNotExist(t *testing.T) {
	log.SetLevel(log.FatalLevel)

	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "not-exist",
			op:    api.OPeq,
			value: "Earth",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Ignore non-existing field. Should be accepted.")
	}

	log.SetLevel(log.DebugLevel)
}

func TestFilterTwoFilters(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "name",
			op:    api.OPeq,
			value: "Sun",
		})
	filters = append(filters,
		restFieldFilter{
			tag:   "size",
			op:    api.OPgt,
			value: "100",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if !rf.Filter(&sun) {
		t.Fatalf("Should be accepted.")
	}
}

func TestFilterTwoFiltersNeg(t *testing.T) {
	var filters []restFieldFilter
	filters = append(filters,
		restFieldFilter{
			tag:   "name",
			op:    api.OPeq,
			value: "Sun",
		})
	filters = append(filters,
		restFieldFilter{
			tag:   "visible",
			op:    api.OPneq,
			value: "true",
		})

	var star Star
	rf := restNewFilter(&star, filters)

	if rf.Filter(&sun) {
		t.Fatalf("Should be filtered.")
	}
}

func TestSortStrAsc(t *testing.T) {
	stars := []*Star{&sun, &sirius, &gliese}
	var data []interface{} = make([]interface{}, len(stars))
	for i, d := range stars {
		data[i] = d
	}

	var sorts []restFieldSort
	sorts = append(sorts, restFieldSort{tag: "name", asc: true})

	restNewSorter(data, sorts).Sort()

	star := data[0].(*Star)
	if star.Name != "Gliese" {
		t.Fatalf("Sort result is wrong: %+v", star)
	}
}

func TestSortInt32Desc(t *testing.T) {
	stars := []*Star{&sun, &sirius, &gliese}
	var data []interface{} = make([]interface{}, len(stars))
	for i, d := range stars {
		data[i] = d
	}

	var sorts []restFieldSort
	sorts = append(sorts, restFieldSort{tag: "mass", asc: false})

	restNewSorter(data, sorts).Sort()

	star := data[0].(*Star)
	if star.Name != "Sirius" {
		t.Fatalf("Sort result is wrong: %+v", star)
	}
}

func TestSortFloatAsc(t *testing.T) {
	stars := []*Star{&sun, &sirius, &gliese}
	var data []interface{} = make([]interface{}, len(stars))
	for i, d := range stars {
		data[i] = d
	}

	var sorts []restFieldSort
	sorts = append(sorts, restFieldSort{tag: "gravity", asc: true})

	restNewSorter(data, sorts).Sort()

	star := data[1].(*Star)
	if star.Name != "Gliese" {
		t.Fatalf("Sort result is wrong: %+v", star)
	}
}

func TestSortBoolDesc(t *testing.T) {
	stars := []*Star{&sun, &sirius, &gliese}
	var data []interface{} = make([]interface{}, len(stars))
	for i, d := range stars {
		data[i] = d
	}

	var sorts []restFieldSort
	sorts = append(sorts, restFieldSort{tag: "visible", asc: false})

	restNewSorter(data, sorts).Sort()

	star := data[2].(*Star)
	if star.Name != "Gliese" {
		t.Fatalf("Sort result is wrong: %+v", star)
	}
}

func TestSortArrayNotSupport(t *testing.T) {
	log.SetLevel(log.FatalLevel)

	stars := []*Star{&sun, &sirius, &gliese}
	var data []interface{} = make([]interface{}, len(stars))
	for i, d := range stars {
		data[i] = d
	}

	var sorts []restFieldSort
	sorts = append(sorts, restFieldSort{tag: "planets", asc: false})

	restNewSorter(data, sorts).Sort()

	star := data[0].(*Star)
	if star.Name != "Sun" {
		t.Fatalf("Sort result is wrong: %+v", star)
	}

	log.SetLevel(log.DebugLevel)
}

func TestSortFieldNotExist(t *testing.T) {
	log.SetLevel(log.FatalLevel)

	stars := []*Star{&sun, &sirius, &gliese}
	var data []interface{} = make([]interface{}, len(stars))
	for i, d := range stars {
		data[i] = d
	}

	var sorts []restFieldSort
	sorts = append(sorts, restFieldSort{tag: "distance", asc: false})

	restNewSorter(data, sorts).Sort()

	star := data[0].(*Star)
	if star.Name != "Sun" {
		t.Fatalf("Sort result is wrong: %+v", star)
	}

	log.SetLevel(log.DebugLevel)
}

func TestQuery(t *testing.T) {
	preTest()

	r, _ := http.NewRequest("GET", "/v1/test?name=v%20lue", nil)
	query := restParseQuery(r)
	if v, ok := query.pairs["name"]; !ok || v != "v lue" {
		t.Errorf("Incorrect query pairs: %+v", query.pairs)
	}

	postTest()
}

func TestRouterParam(t *testing.T) {
	preTest()

	router = httprouter.New()
	router.GET("/v1/user/:name", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		name := ps.ByName("name")
		if name != "joe#default" {
			t.Errorf("Incorrect httprouter param: %+v", name)
		}
	})

	w := new(mockResponseWriter)
	r, _ := http.NewRequest("GET", "/v1/user/joe%23default", nil)
	router.ServeHTTP(w, r)

	postTest()
}

type Director struct {
	Director string `json:"name"`
	Sex      bool   `json:"sex"`
	Age      int    `json:"age"`
}

type Studio struct {
	Studio   string `json:"name"`
	Location string `json:"location"`
}

type Movie struct {
	Movie  string `json:"name"`
	Length int    `json:"length"`
	Director
	*Studio
}

func TestFilterEmbedded(t *testing.T) {
	var m Movie

	rf := restNewFilter(&m, nil)
	if rf.tags["length"] != "Length" {
		t.Errorf("Tag parsing error: tags=%+v age=%v", rf.tags, rf.tags["age"])
	}
	if rf.tags["age"] != "Age" {
		t.Errorf("Tag parsing error: tags=%+v age=%v", rf.tags, rf.tags["age"])
	}
	if rf.tags["name"] != "Movie" {
		t.Errorf("Tag parsing error: tags=%+v movie=%v", rf.tags, rf.tags["name"])
	}

	if _, ok := rf.tags["location"]; ok {
		t.Errorf("Embedded pointer should be ignored")
	}
	/*
		// The following code give panic - panic: reflect: indirection through nil pointer to embedded struct
		v := reflect.ValueOf(&m).Elem()
		f := v.FieldByName("Location")
		if !f.IsValid() {
			t.Errorf("Tag parsing error: ")
		}
	*/
}

func TestSorterEmbedded(t *testing.T) {
	var m Movie
	data := []interface{}{&m}

	rs := restNewSorter(data, nil)
	if rs.tags["length"] != "Length" {
		t.Errorf("Tag parsing error: tags=%+v age=%v", rs.tags, rs.tags["age"])
	}
	if rs.tags["age"] != "Age" {
		t.Errorf("Tag parsing error: tags=%+v age=%v", rs.tags, rs.tags["age"])
	}
	if rs.tags["name"] != "Movie" {
		t.Errorf("Tag parsing error: tags=%+v movie=%v", rs.tags, rs.tags["name"])
	}

	if _, ok := rs.tags["location"]; ok {
		t.Errorf("Embedded pointer should be ignored")
	}
}

func TestObjectNameValidation(t *testing.T) {
	good := []string{
		"abc123",
		"abc:123",
		"abc-123",
		"abc_123",
		"abc.123",
	}
	bad := []string{
		"/abc123",
		".abc123",
		":abc123",
		"_abc123",
		"abc\\123",
		"abc 123",
		"abc123 ",
		" abc123",
		"abc%123",
		"abc<123>",
	}
	for _, e := range good {
		if isObjectNameValid(e) == false {
			t.Errorf("Object name validation false positive: %s", e)
		}
	}
	for _, e := range bad {
		if isObjectNameValid(e) == true {
			t.Errorf("Object name validation false negative: %s", e)
		}
	}
}

func TestObjectNameWithSpaceValidation(t *testing.T) {
	good := []string{
		"abc123",
		"abc:123",
		"abc-123",
		"abc_123",
		"abc.123",
		"abc 123",
		"abc  123",
	}
	bad := []string{
		"/abc123",
		".abc123",
		":abc123",
		"_abc123",
		"abc\\123",
		"abc123 ",
		" abc123",
		"abc%123",
		"abc<123>",
	}
	for _, e := range good {
		if isObjectNameWithSpaceValid(e) == false {
			t.Errorf("Object name validation false positive: %s", e)
		}
	}
	for _, e := range bad {
		if isObjectNameWithSpaceValid(e) == true {
			t.Errorf("Object name validation false negative: %s", e)
		}
	}
}

func TestNamePathValidation(t *testing.T) {
	good := []string{
		"abc123",
		"abc:123",
		"abc-123",
		"abc_123",
		"abc.123",
		"abc:123/",
		"/abc123",
		"abc:-1._23/",
		"https://mydomain.com/groups",
	}
	bad := []string{
		".abc123",
		":abc123",
		"_abc123",
		"abc\\123",
		"abc 123",
		"abc123 ",
		" abc123",
		"abc%123",
		"abc<123>",
	}
	for _, e := range good {
		if isNamePathValid(e) == false {
			t.Errorf("Object name validation false positive: %s", e)
		}
	}
	for _, e := range bad {
		if isNamePathValid(e) == true {
			t.Errorf("Object name validation false negative: %s", e)
		}
	}
}

func TestNewestVersion(t *testing.T) {
	vers := utils.NewSet("1.0", "1.1", "1.2")
	if getNewestVersion(vers) != "1.2" {
		t.Errorf("Incorrect newest version: %v %s", vers, getNewestVersion(vers))
	}

	vers = utils.NewSet("1.0")
	if getNewestVersion(vers) != "1.0" {
		t.Errorf("Incorrect newest version: %v %s", vers, getNewestVersion(vers))
	}

	vers = utils.NewSet()
	if getNewestVersion(vers) != "" {
		t.Errorf("Incorrect newest version: %v %s", vers, getNewestVersion(vers))
	}

	vers = utils.NewSet("1.0", "1.1", "1.2.b1", "1.2")
	if getNewestVersion(vers) != "1.2" {
		t.Errorf("Incorrect newest version: %v %s", vers, getNewestVersion(vers))
	}

	vers = utils.NewSet("")
	if getNewestVersion(vers) != "" {
		t.Errorf("Incorrect newest version: %v %s", vers, getNewestVersion(vers))
	}

	vers = utils.NewSet("1.0", "a.b")
	if getNewestVersion(vers) != "1.0" {
		t.Errorf("Incorrect newest version: %v %s", vers, getNewestVersion(vers))
	}
}

func TestInitSearchRegistries(t *testing.T) {
	var ctx Context

	ctx.SearchRegistries = "docker.io, index.docker.io/library ,http://registry.hub.docker.com:8080/lib,https://registry-1.docker.io/ , http://local.registry.net:8080/abc "
	initSearchRegistries(&ctx)
	expected := []string{
		"https://docker.io/",
		"https://index.docker.io/",
		"http://registry.hub.docker.com:8080/",
		"https://registry-1.docker.io/",
		"http://local.registry.net:8080/",
	}
	if searchRegistries.Cardinality() != len(expected) {
		t.Errorf("Unexpected searchRegistries result: %+v\n", searchRegistries)
	} else {
		for _, reg := range expected {
			if !searchRegistries.Contains(reg) {
				t.Errorf("Expected element not found in searchRegistries: %+v\n", reg)
			}
		}
	}
}
