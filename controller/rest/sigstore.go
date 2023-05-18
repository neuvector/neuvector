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

	body, _ := ioutil.ReadAll(r.Body)
	var rootOfTrust api.REST_SigstoreRootOfTrust_POST
	err := json.Unmarshal(body, &rootOfTrust)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	if rootOfTrust.Name == "" {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Field \"name\" cannot be empty.")
		return
	}

	clusRootOfTrust := share.CLUSSigstoreRootOfTrust{
		Name:           rootOfTrust.Name,
		IsPrivate:      rootOfTrust.IsPrivate,
		RekorPublicKey: rootOfTrust.RekorPublicKey,
		RootCert:       rootOfTrust.RootCert,
		SCTPublicKey:   rootOfTrust.SCTPublicKey,
		CfgType:        rootOfTrust.CfgType,
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
		resp.Verifiers = make(map[string]api.REST_SigstoreVerifier, len(verifiers))
		for name, verifier := range verifiers {
			resp.Verifiers[name] = CLUSVerifierToRESTVerifier(verifier)
		}
	}
	restRespSuccess(w, r, resp, nil, nil, nil, fmt.Sprintf("Retrieved Sigstore Root Of Trust \"%s\"", rootName))
}

func handlerSigstoreRootOfTrustPatchByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

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
	var restRootOfTrust *api.REST_SigstoreRootOfTrust_PATCH
	err = json.Unmarshal(body, restRootOfTrust)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	updateCLUSRoot(clusRootOfTrust, restRootOfTrust)

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

	rootsOfTrust, err := clusHelper.GetAllSigstoreRootsOfTrust()
	if err != nil {
		msg := fmt.Sprintf("could not retrieve sigstore roots of trust from kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
		return
	}

	resp := make(map[string]api.REST_SigstoreRootOfTrust_GET, len(rootsOfTrust))
	for key, rootOfTrust := range rootsOfTrust {
		restRootOfTrust := CLUSRootToRESTRoot_GET(rootOfTrust)
		if withVerifiers(r) {
			verifiers, err := clusHelper.GetAllSigstoreVerifiersForRoot(key)
			if err != nil {
				msg := fmt.Sprintf("could not retrieve verifiers for root \"%s\": %s", key, err.Error())
				restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
				return
			}
			restRootOfTrust.Verifiers = make(map[string]api.REST_SigstoreVerifier, len(verifiers))
			for name, verifier := range verifiers {
				restRootOfTrust.Verifiers[name] = CLUSVerifierToRESTVerifier(verifier)
			}
		}
		resp[key] = restRootOfTrust
	}
	restRespSuccess(w, r, &resp, nil, nil, nil, "Get all sigstore roots of trust")
}

func handlerSigstoreVerifierPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	body, _ := ioutil.ReadAll(r.Body)
	var verifier api.REST_SigstoreVerifier
	err := json.Unmarshal(body, &verifier)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
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
	}

	if validationError := validateCLUSVerifier(clusVerifier); validationError != nil {
		msg := fmt.Sprintf("Invalid verifier in request: %s", validationError.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
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
	var restVerifier *api.REST_SigstoreVerifier_PATCH
	err = json.Unmarshal(body, restVerifier)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	updateCLUSVerifier(clusVerifier, restVerifier)

	if validationError := validateCLUSVerifier(*clusVerifier); validationError != nil {
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
	
	rootName := ps.ByName("root_name")
	verifiers, err := clusHelper.GetAllSigstoreVerifiersForRoot(rootName)
	if err != nil {
		msg := fmt.Sprintf("could not retrieve sigstore verifiers from kv store for root \"%s\": %s", rootName, err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
		return
	}

	resp := make(map[string]api.REST_SigstoreVerifier, len(verifiers))
	for key, verifier := range verifiers {
		resp[key] = CLUSVerifierToRESTVerifier(verifier)
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
		CfgType:        clusRoot.CfgType,
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
	}
}

func withVerifiers(r *http.Request) bool {
	q := r.URL.Query()
	return q.Get("with_verifiers") == "true"
}

func validateCLUSVerifier(verifier share.CLUSSigstoreVerifier) error {
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
	} else {
		if verifier.CertIssuer == "" || verifier.CertSubject == "" {
			return errors.New("fields \"cert_subject\" and \"cert_issuer\" cannot be empty for a verifier of type \"keyless\"")
		}
	}
	return nil
}

func updateCLUSRoot(clusRoot *share.CLUSSigstoreRootOfTrust, updates *api.REST_SigstoreRootOfTrust_PATCH) {
	if updates.IsPrivate != nil {
		clusRoot.IsPrivate = *updates.IsPrivate
	}

	if updates.RekorPublicKey != nil {
		clusRoot.RekorPublicKey = *updates.RekorPublicKey
	}

	if updates.RootCert != nil {
		clusRoot.RootCert = *updates.RootCert
	}

	if updates.SCTPublicKey != nil {
		clusRoot.SCTPublicKey = *updates.SCTPublicKey
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

	if updates.PublicKey != nil {
		clusVerifier.PublicKey = *updates.PublicKey
	}

	if updates.CertIssuer != nil {
		clusVerifier.CertIssuer = *updates.CertIssuer
	}

	if updates.CertSubject != nil {
		clusVerifier.CertSubject = *updates.CertSubject
	}
}
