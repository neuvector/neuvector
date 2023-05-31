package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
)

func handlerSigstoreRootOfTrustPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreRootOfTrust{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)
	var rootOfTrust api.REST_SigstoreRootOfTrust_POST
	err := json.Unmarshal(body, &rootOfTrust)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	} else if !isObjectNameValid(rootOfTrust.Name) {
		e := "Invalid characters in name"
		log.WithFields(log.Fields{"name": rootOfTrust.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	if rootOfTrust.IsPrivate {
		if rootOfTrust.RekorPublicKey == "" && rootOfTrust.RootCert == "" && rootOfTrust.SCTPublicKey == "" {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "empty keys")
			return
		}
	} else {
		rootOfTrust.RekorPublicKey = ""
		rootOfTrust.RootCert = ""
		rootOfTrust.SCTPublicKey = ""
	}

	clusRootOfTrust := share.CLUSSigstoreRootOfTrust{
		Name:           rootOfTrust.Name,
		IsPrivate:      rootOfTrust.IsPrivate,
		RekorPublicKey: rootOfTrust.RekorPublicKey,
		RootCert:       rootOfTrust.RootCert,
		SCTPublicKey:   rootOfTrust.SCTPublicKey,
		CfgType:        share.UserCreated,
		Comment:        rootOfTrust.Comment,
	}

	err = clusHelper.CreateSigstoreRootOfTrust(&clusRootOfTrust, nil)
	if err != nil {
		msg := fmt.Sprintf("could not save root of trust to kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, msg)
		return
	}

	msg := fmt.Sprintf("Added verifier \"%s\"", clusRootOfTrust.Name)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreRootOfTrustGetByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreRootOfTrust{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	rootName := ps.ByName("root_name")
	rootOfTrust, _, err := clusHelper.GetSigstoreRootOfTrust(rootName)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, err.Error())
		return
	}
	if rootOfTrust == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrNotFound)
	}
	resp := CLUSRootToRESTRoot_GET(rootOfTrust)
	if withVerifiers(r) {
		verifiers, err := clusHelper.GetAllSigstoreVerifiersForRoot(rootName)
		if err != nil {
			msg := fmt.Sprintf("could not retrieve verifiers for root \"%s\": %s", rootName, err.Error())
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
			return
		}
		for _, verifier := range verifiers {
			resp.Verifiers = append(resp.Verifiers, CLUSVerifierToRESTVerifier(verifier))
		}
	}
	restRespSuccess(w, r, resp, nil, nil, nil, fmt.Sprintf("Retrieved Sigstore Root Of Trust \"%s\"", rootName))
}

func handlerSigstoreRootOfTrustPatchByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreRootOfTrust{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	rootName := ps.ByName("root_name")
	clusRootOfTrust, rev, err := clusHelper.GetSigstoreRootOfTrust(rootName)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, err.Error())
		return
	}
	if clusRootOfTrust == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrNotFound)
	}

	body, _ := ioutil.ReadAll(r.Body)
	var restRootOfTrust api.REST_SigstoreRootOfTrust_PATCH
	err = json.Unmarshal(body, &restRootOfTrust)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	updateCLUSRoot(clusRootOfTrust, &restRootOfTrust)
	if clusRootOfTrust.IsPrivate && clusRootOfTrust.RekorPublicKey == "" && clusRootOfTrust.RootCert == "" && clusRootOfTrust.SCTPublicKey == "" {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "empty keys")
		return
	}

	err = clusHelper.UpdateSigstoreRootOfTrust(clusRootOfTrust, nil, rev)
	if err != nil {
		msg := fmt.Sprintf("could not save root of trust to kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	msg := fmt.Sprintf("Added root of trust \"%s\"", clusRootOfTrust.Name)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreRootOfTrustDeleteByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreRootOfTrust{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	rootName := ps.ByName("root_name")
	err := clusHelper.DeleteSigstoreRootOfTrust(rootName)
	if err != nil {
		msg := fmt.Sprintf("could not delete root of trust \"%s\" from kv store: %s", rootName, err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, msg)
		return
	}
	msg := fmt.Sprintf("Deleted root of trust \"%s\"", rootName)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreRootOfTrustGetAll(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreRootOfTrust{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	clusRootsOfTrust, err := clusHelper.GetAllSigstoreRootsOfTrust()
	if err != nil {
		msg := fmt.Sprintf("could not retrieve sigstore roots of trust from kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
		return
	}

	rootsOfTrust := []api.REST_SigstoreRootOfTrust_GET{}
	for _, clusRootOfTrust := range clusRootsOfTrust {
		rootOfTrust := CLUSRootToRESTRoot_GET(clusRootOfTrust)
		if withVerifiers(r) {
			verifiers, err := clusHelper.GetAllSigstoreVerifiersForRoot(clusRootOfTrust.Name)
			if err != nil {
				msg := fmt.Sprintf("could not retrieve verifiers for root \"%s\": %s", clusRootOfTrust.Name, err.Error())
				restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
				return
			}
			for _, verifier := range verifiers {
				rootOfTrust.Verifiers = append(rootOfTrust.Verifiers, CLUSVerifierToRESTVerifier(verifier))
			}
		}
		rootsOfTrust = append(rootsOfTrust, rootOfTrust)
	}

	resp := api.REST_SigstoreRootOfTrustCollection{RootsOfTrust: rootsOfTrust}
	restRespSuccess(w, r, &resp, nil, nil, nil, "Get all sigstore roots of trust")
}

func handlerSigstoreVerifierPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreVerifier{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)
	var verifier api.REST_SigstoreVerifier
	err := json.Unmarshal(body, &verifier)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	} else if !isObjectNameValid(verifier.Name) {
		e := "Invalid characters in name"
		log.WithFields(log.Fields{"name": verifier.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	clusVerifier := share.CLUSSigstoreVerifier{
		Name:         verifier.Name,
		VerifierType: verifier.VerifierType,
		IgnoreTLog:   verifier.IgnoreTLog,
		IgnoreSCT:    verifier.IgnoreSCT,
		PublicKey:    verifier.PublicKey,
		CertIssuer:   verifier.CertIssuer,
		CertSubject:  verifier.CertSubject,
		Comment:      verifier.Comment,
	}

	if validationError := validateCLUSVerifier(&clusVerifier); validationError != nil {
		msg := fmt.Sprintf("Invalid verifier in request: %s", validationError.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	if verifier.VerifierType == "keyless" {
		verifier.PublicKey = ""
	} else if verifier.VerifierType == "keypair" {
		verifier.CertIssuer = ""
		verifier.CertSubject = ""
	}

	err = clusHelper.CreateSigstoreVerifier(ps.ByName("root_name"), &clusVerifier, nil)
	if err != nil {
		msg := fmt.Sprintf("could not save verifier to kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	msg := fmt.Sprintf("Added verifier \"%s\"", clusVerifier.Name)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreVerifierGetByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreVerifier{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	rootName := ps.ByName("root_name")
	verifierName := ps.ByName("verifier_name")
	verifier, _, err := clusHelper.GetSigstoreVerifier(rootName, verifierName)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, err.Error())
		return
	}
	if verifier == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrNotFound)
	}
	resp := CLUSVerifierToRESTVerifier(verifier)
	restRespSuccess(w, r, resp, nil, nil, nil, fmt.Sprintf("Retrieved Sigstore Verifier \"%s/%s\"", rootName, verifierName))
}

func handlerSigstoreVerifierPatchByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreVerifier{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	rootName := ps.ByName("root_name")
	verifierName := ps.ByName("verifier_name")
	clusVerifier, rev, err := clusHelper.GetSigstoreVerifier(rootName, verifierName)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, err.Error())
		return
	}
	if clusVerifier == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrNotFound)
	}

	body, _ := ioutil.ReadAll(r.Body)
	var restVerifier api.REST_SigstoreVerifier_PATCH
	err = json.Unmarshal(body, &restVerifier)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	updateCLUSVerifier(clusVerifier, &restVerifier)

	if validationError := validateCLUSVerifier(clusVerifier); validationError != nil {
		msg := fmt.Sprintf("Patch would result in invalid verifier: %s", validationError.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	err = clusHelper.UpdateSigstoreVerifier(rootName, clusVerifier, nil, rev)
	if err != nil {
		msg := fmt.Sprintf("could not save verifier to kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	msg := fmt.Sprintf("Added verifier \"%s\"", clusVerifier.Name)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreVerifierDeleteByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreVerifier{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	rootName := ps.ByName("root_name")
	verifierName := ps.ByName("verifier_name")
	err := clusHelper.DeleteSigstoreVerifier(rootName, verifierName)
	if err != nil {
		msg := fmt.Sprintf("could not delete verifier \"%s/%s\" from kv store: %s", rootName, verifierName, err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, msg)
		return
	}
	msg := fmt.Sprintf("Deleted root of trust \"%s/%s\"", rootName, verifierName)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreVerifierGetAll(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSSigstoreVerifier{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	rootName := ps.ByName("root_name")
	clusVerifiers, err := clusHelper.GetAllSigstoreVerifiersForRoot(rootName)
	if err != nil {
		msg := fmt.Sprintf("could not retrieve sigstore verifiers from kv store for root \"%s\": %s", rootName, err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
		return
	}

	resp := api.REST_SigstoreVerifierCollection{}
	for _, clusVerifier := range clusVerifiers {
		resp.Verifiers = append(resp.Verifiers, CLUSVerifierToRESTVerifier(clusVerifier))
	}
	restRespSuccess(w, r, &resp, nil, nil, nil, "Get all sigstore verifiers")
}

func CLUSRootToRESTRoot_GET(clusRoot *share.CLUSSigstoreRootOfTrust) api.REST_SigstoreRootOfTrust_GET {
	return api.REST_SigstoreRootOfTrust_GET{
		Name:           clusRoot.Name,
		IsPrivate:      clusRoot.IsPrivate,
		RekorPublicKey: clusRoot.RekorPublicKey,
		RootCert:       clusRoot.RootCert,
		SCTPublicKey:   clusRoot.SCTPublicKey,
		CfgType:        cfgTypeMap2Api[clusRoot.CfgType],
		Comment:        clusRoot.Comment,
	}
}

func CLUSVerifierToRESTVerifier(clusVerifier *share.CLUSSigstoreVerifier) api.REST_SigstoreVerifier {
	return api.REST_SigstoreVerifier{
		Name:         clusVerifier.Name,
		VerifierType: clusVerifier.VerifierType,
		IgnoreTLog:   clusVerifier.IgnoreTLog,
		IgnoreSCT:    clusVerifier.IgnoreSCT,
		PublicKey:    clusVerifier.PublicKey,
		CertIssuer:   clusVerifier.CertIssuer,
		CertSubject:  clusVerifier.CertSubject,
		Comment:      clusVerifier.Comment,
	}
}

func withVerifiers(r *http.Request) bool {
	q := r.URL.Query()
	return q.Get("with_verifiers") == "true"
}

func validateCLUSVerifier(verifier *share.CLUSSigstoreVerifier) error {
	if verifier.Name == "" || verifier.VerifierType == "" {
		return errors.New("fields \"name\" and \"type\" cannot be empty")
	}

	if verifier.VerifierType != "keyless" && verifier.VerifierType != "keypair" {
		return errors.New("field \"type\" must be either \"keyless\" or \"keypair\"")
	}

	if verifier.VerifierType == "keypair" {
		if verifier.PublicKey == "" {
			return errors.New("field \"public_key\" cannot be empty for a verifier of type \"keypair\"")
		}
		verifier.CertIssuer = ""
		verifier.CertSubject = ""
	} else {
		if verifier.CertIssuer == "" || verifier.CertSubject == "" {
			return errors.New("fields \"cert_subject\" and \"cert_issuer\" cannot be empty for a verifier of type \"keyless\"")
		}
		verifier.PublicKey = ""
	}
	return nil
}

func updateCLUSRoot(clusRoot *share.CLUSSigstoreRootOfTrust, updates *api.REST_SigstoreRootOfTrust_PATCH) {
	if updates.IsPrivate != nil {
		clusRoot.IsPrivate = *updates.IsPrivate
	}

	if clusRoot.IsPrivate {
		if updates.RekorPublicKey != nil {
			clusRoot.RekorPublicKey = *updates.RekorPublicKey
		}

		if updates.RootCert != nil {
			clusRoot.RootCert = *updates.RootCert
		}

		if updates.SCTPublicKey != nil {
			clusRoot.SCTPublicKey = *updates.SCTPublicKey
		}
	} else {
		clusRoot.RekorPublicKey = ""
		clusRoot.RootCert = ""
		clusRoot.SCTPublicKey = ""
	}

	if updates.Comment != nil {
		clusRoot.Comment = *updates.Comment
	}
}

func updateCLUSVerifier(clusVerifier *share.CLUSSigstoreVerifier, updates *api.REST_SigstoreVerifier_PATCH) {
	if updates.VerifierType != nil {
		clusVerifier.VerifierType = *updates.VerifierType
	}

	if updates.IgnoreTLog != nil {
		clusVerifier.IgnoreTLog = *updates.IgnoreTLog
	}

	if updates.IgnoreSCT != nil {
		clusVerifier.IgnoreSCT = *updates.IgnoreSCT
	}

	if clusVerifier.VerifierType == "keypair" {
		if updates.PublicKey != nil {
			clusVerifier.PublicKey = *updates.PublicKey
		}
		clusVerifier.CertIssuer = ""
		clusVerifier.CertSubject = ""
	}

	if clusVerifier.VerifierType == "keyless" {
		if updates.CertIssuer != nil {
			clusVerifier.CertIssuer = *updates.CertIssuer
		}

		if updates.CertSubject != nil {
			clusVerifier.CertSubject = *updates.CertSubject
		}
		clusVerifier.PublicKey = ""
	}

	if updates.Comment != nil {
		clusVerifier.Comment = *updates.Comment
	}
}
