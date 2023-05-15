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
)

func handlerSigstoreRootOfTrustPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	body, _ := ioutil.ReadAll(r.Body)
	var rootOfTrust api.RESTSigstoreRootOfTrust
	err := json.Unmarshal(body, &rootOfTrust)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	if *rootOfTrust.Name == "" {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Field \"name\" cannot be empty.")
		return
	}

	clusRootOfTrust := share.CLUSSigstoreRootOfTrust{
		Name:           *rootOfTrust.Name,
		RekorPublicKey: *rootOfTrust.RekorPublicKey,
		RootCert:       *rootOfTrust.RootCert,
		SCTPublicKey:   *rootOfTrust.SCTPublicKey,
	}

	err = clusHelper.PutSigstoreRootOfTrust(&clusRootOfTrust)
	if err != nil {
		msg := fmt.Sprintf("could not save root of trust to kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, msg)
		return
	}

	msg := fmt.Sprintf("Added verifier \"%s\"", clusRootOfTrust.Name)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreRootOfTrustGetByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	rootName := ps.ByName("root_name")
	rootOfTrust, err := clusHelper.GetSigstoreRootOfTrust(rootName)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, err.Error())
		return
	}
	if rootOfTrust == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrNotFound)
	}
	resp := CLUSRootToRESTRoot(rootOfTrust)
	if withVerifiers(r) {
		verifiers, err := clusHelper.GetAllSigstoreVerifiersForRoot(rootName)
		if err != nil {
			msg := fmt.Sprintf("could not retrieve verifiers for root \"%s\": %s", rootName, err.Error())
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
			return
		}
		resp.Verifiers = make(map[string]api.RESTSigstoreVerifier, len(verifiers))
		for name, verifier := range verifiers {
			resp.Verifiers[name] = CLUSVerifierToRESTVerifier(verifier)
		}
	}
	restRespSuccess(w, r, resp, nil, nil, nil, fmt.Sprintf("Retrieved Sigstore Root Of Trust \"%s\"", rootName))
}

func handlerSigstoreRootOfTrustPatchByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	rootName := ps.ByName("root_name")
	clusRootOfTrust, err := clusHelper.GetSigstoreRootOfTrust(rootName)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, err.Error())
		return
	}
	if clusRootOfTrust == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrNotFound)
	}

	body, _ := ioutil.ReadAll(r.Body)
	var restRootOfTrust *api.RESTSigstoreRootOfTrust
	err = json.Unmarshal(body, restRootOfTrust)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	updateCLUSRoot(clusRootOfTrust, restRootOfTrust)

	err = clusHelper.PutSigstoreRootOfTrust(clusRootOfTrust)
	if err != nil {
		msg := fmt.Sprintf("could not save root of trust to kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	msg := fmt.Sprintf("Added root of trust \"%s\"", clusRootOfTrust.Name)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreRootOfTrustDeleteByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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
	rootsOfTrust, err := clusHelper.GetAllSigstoreRootsOfTrust()
	if err != nil {
		msg := fmt.Sprintf("could not retrieve sigstore roots of trust from kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
		return
	}

	resp := make(map[string]api.RESTSigstoreRootOfTrust, len(rootsOfTrust))
	for key, rootOfTrust := range rootsOfTrust {
		restRootOfTrust := CLUSRootToRESTRoot(rootOfTrust)
		if withVerifiers(r) {
			verifiers, err := clusHelper.GetAllSigstoreVerifiersForRoot(key)
			if err != nil {
				msg := fmt.Sprintf("could not retrieve verifiers for root \"%s\": %s", key, err.Error())
				restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
				return
			}
			restRootOfTrust.Verifiers = make(map[string]api.RESTSigstoreVerifier, len(verifiers))
			for name, verifier := range verifiers {
				restRootOfTrust.Verifiers[name] = CLUSVerifierToRESTVerifier(verifier)
			}
		}
		resp[key] = restRootOfTrust
	}
	restRespSuccess(w, r, &resp, nil, nil, nil, "Get all sigstore roots of trust")
}

func handlerSigstoreVerifierPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	body, _ := ioutil.ReadAll(r.Body)
	var verifier api.RESTSigstoreVerifier
	err := json.Unmarshal(body, &verifier)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	if validationError := validateRESTVerifier(verifier); validationError != nil {
		msg := fmt.Sprintf("Invalid verifier in request: %s", validationError.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	clusVerifier := share.CLUSSigstoreVerifier{
		Name:       *verifier.Name,
		Type:       *verifier.Type,
		IgnoreTLog: *verifier.IgnoreTLog,
		IgnoreSCT:  *verifier.IgnoreSCT,
	}

	if *verifier.Type == "keypair" {
		clusVerifier.KeypairOptions.PublicKey = *verifier.KeypairOptions.PublicKey
	} else {
		clusVerifier.KeylessOptions.CertIssuer = *verifier.KeylessOptions.CertIssuer
		clusVerifier.KeylessOptions.CertSubject = *verifier.KeylessOptions.CertSubject
	}

	err = clusHelper.PutSigstoreVerifier(ps.ByName("root_name"), &clusVerifier)
	if err != nil {
		msg := fmt.Sprintf("could not save verifier to kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	msg := fmt.Sprintf("Added verifier \"%s\"", clusVerifier.Name)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreVerifierGetByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	rootName := ps.ByName("root_name")
	verifierName := ps.ByName("verifier_name")
	verifier, err := clusHelper.GetSigstoreVerifier(rootName, verifierName)
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
	rootName := ps.ByName("root_name")
	verifierName := ps.ByName("verifier_name")
	clusVerifier, err := clusHelper.GetSigstoreVerifier(rootName, verifierName)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, err.Error())
		return
	}
	if clusVerifier == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrNotFound)
	}

	body, _ := ioutil.ReadAll(r.Body)
	var restVerifier *api.RESTSigstoreVerifier
	err = json.Unmarshal(body, restVerifier)
	if err != nil {
		msg := fmt.Sprintf("could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	updateCLUSVerifier(clusVerifier, restVerifier)

	if validationError := validateRESTVerifier(CLUSVerifierToRESTVerifier(clusVerifier)); validationError != nil {
		msg := fmt.Sprintf("Patch would result in invalid verifier: %s", validationError.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	err = clusHelper.PutSigstoreVerifier(rootName, clusVerifier)
	if err != nil {
		msg := fmt.Sprintf("could not save verifier to kv store: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	msg := fmt.Sprintf("Added verifier \"%s\"", clusVerifier.Name)
	restRespSuccess(w, r, nil, nil, nil, nil, msg)
}

func handlerSigstoreVerifierDeleteByName(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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
	rootName := ps.ByName("root_name")
	verifiers, err := clusHelper.GetAllSigstoreVerifiersForRoot(rootName)
	if err != nil {
		msg := fmt.Sprintf("could not retrieve sigstore verifiers from kv store for root \"%s\": %s", rootName, err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailReadCluster, msg)
		return
	}

	resp := make(map[string]api.RESTSigstoreVerifier, len(verifiers))
	for key, verifier := range verifiers {
		resp[key] = CLUSVerifierToRESTVerifier(verifier)
	}
	restRespSuccess(w, r, &resp, nil, nil, nil, "Get all sigstore verifiers")
}

func CLUSRootToRESTRoot(clusRoot *share.CLUSSigstoreRootOfTrust) api.RESTSigstoreRootOfTrust {
	return api.RESTSigstoreRootOfTrust{
		Name:           &clusRoot.Name,
		RekorPublicKey: &clusRoot.RekorPublicKey,
		RootCert:       &clusRoot.RootCert,
		SCTPublicKey:   &clusRoot.SCTPublicKey,
	}
}

func CLUSVerifierToRESTVerifier(clusVerifier *share.CLUSSigstoreVerifier) api.RESTSigstoreVerifier {
	return api.RESTSigstoreVerifier{
		Name:       &clusVerifier.Name,
		Type:       &clusVerifier.Type,
		IgnoreTLog: &clusVerifier.IgnoreTLog,
		IgnoreSCT:  &clusVerifier.IgnoreSCT,
		KeypairOptions: &api.RESTSigstoreVerifierKeypairOptions{
			PublicKey: &clusVerifier.KeypairOptions.PublicKey,
		},
		KeylessOptions: &api.RESTSigstoreVerifierKeylessOptions{
			CertIssuer:  &clusVerifier.KeylessOptions.CertIssuer,
			CertSubject: &clusVerifier.KeylessOptions.CertSubject,
		},
	}
}

func withVerifiers(r *http.Request) bool {
	q := r.URL.Query()
	return q.Get("with_verifiers") == "true"
}

func validateRESTVerifier(verifier api.RESTSigstoreVerifier) error {
	if *verifier.Name == "" || *verifier.Type == "" {
		return errors.New("fields \"name\" and \"type\" cannot be empty")
	}

	if *verifier.Type != "keyless" && *verifier.Type != "keypair" {
		return errors.New("field \"type\" must be either \"keyless\" or \"keypair\"")
	}

	if *verifier.Type == "keypair" {
		if verifier.KeypairOptions == nil {
			return errors.New("field \"keypair_options\" is required for a verifier of type \"keypair\"")
		}
		if *verifier.KeypairOptions.PublicKey == "" {
			return errors.New("field \"public_key\" cannot be empty for a verifier of type \"keypair\"")
		}
	} else {
		if verifier.KeylessOptions == nil {
			return errors.New("field \"keyless_options\" is required for a verifier of type \"keyless\"")
		}
		if *verifier.KeylessOptions.CertIssuer == "" || *verifier.KeylessOptions.CertSubject == "" {
			return errors.New("fields \"cert_subject\" and \"cert_issuer\" in field \"keyless_options\" cannot be empty for a verifier of type \"keyless\"")
		}
	}
	return nil
}

func updateCLUSRoot(clusRoot *share.CLUSSigstoreRootOfTrust, updates *api.RESTSigstoreRootOfTrust) {
	if updates.Name != nil {
		clusRoot.Name = *updates.Name
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
}

func updateCLUSVerifier(clusVerifier *share.CLUSSigstoreVerifier, updates *api.RESTSigstoreVerifier) {
	if updates.Name != nil {
		clusVerifier.Name = *updates.Name
	}

	if updates.Type != nil {
		clusVerifier.Type = *updates.Type
	}

	if updates.IgnoreTLog != nil {
		clusVerifier.IgnoreTLog = *updates.IgnoreTLog
	}

	if updates.IgnoreSCT != nil {
		clusVerifier.IgnoreSCT = *updates.IgnoreSCT
	}

	if updates.KeylessOptions != nil {
		if updates.KeylessOptions.CertIssuer != nil {
			clusVerifier.KeylessOptions.CertIssuer = *updates.KeylessOptions.CertIssuer
		}

		if updates.KeylessOptions.CertSubject != nil {
			clusVerifier.KeylessOptions.CertSubject = *updates.KeylessOptions.CertSubject
		}
	}

	if updates.KeypairOptions != nil {
		if updates.KeypairOptions.PublicKey != nil {
			clusVerifier.KeypairOptions.PublicKey = *updates.KeypairOptions.PublicKey
		}
	}
}
