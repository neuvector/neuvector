package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"

	manifestList "github.com/docker/distribution/manifest/manifestlist"
	manifestV1 "github.com/docker/distribution/manifest/schema1"
	manifestV2 "github.com/docker/distribution/manifest/schema2"
	goDigest "github.com/opencontainers/go-digest"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httptrace"
	"github.com/neuvector/neuvector/share/scan/registry"
)

const mediaTypeCosign = "application/vnd.dev.cosign.simplesigning.v1+json"
const quayRegistryURL = "https://quay.io"
const cosignSignatureTagSuffix = ".sig"

type RegClient struct {
	*registry.Registry
}

// If token is given, the Authorization header will be added with token appended.
func NewRegClient(url, token, username, password, proxy string, trace httptrace.HTTPTrace) *RegClient {
	log.WithFields(log.Fields{"url": url}).Debug("")

	// Ignore errors
	hub, _, _ := registry.NewInsecure(url, token, username, password, proxy, trace)
	return &RegClient{Registry: hub}
}

type ImageInfo struct {
	Layers           []string
	ID               string
	Digest           string
	Author           string
	Signed           bool
	RunAsRoot        bool
	Envs             []string
	Cmds             []string
	Labels           map[string]string
	Sizes            map[string]int64
	RepoTags         []string
	IsSignatureImage bool
	RawManifest      []byte
}

// SignatureData represents signature image data retrieved from the registry to be
// used in verification.
type SignatureData struct {
	// The raw manifest JSON retrieved from the registry
	Manifest string `json:"Manifest"`

	// A collection of signature payloads referenced by the manifest to be verified.
	Payloads map[string]string `json:"Payloads"`
}

func IsPotentialCosignSignatureTag(tag string) bool {
	return (strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, cosignSignatureTagSuffix))
}

func IsQuayRegistry(rc *RegClient) bool {
	return strings.EqualFold(rc.URL[:len(quayRegistryURL)], quayRegistryURL)
}

func (rc *RegClient) copyV2LayerAndHistory(imageInfo *ImageInfo, manV2 *manifestV2.Manifest, ccmi *registry.ManifestInfo) bool {
	allLayersAreCosignPayloads := true

	// In the history list from container image config spec, only the layer that has no empty_layer flag
	// has a digest in the manifest layer list.
	// The following section bring the layer list in imageInfo to the same size as history (cmd)
	j := len(manV2.Layers) - 1
	for i := 0; i < len(ccmi.Cmds); i++ {
		if (ccmi != nil && ccmi.EmptyLayers[i]) || j < 0 {
			imageInfo.Layers = append(imageInfo.Layers, "")
		} else {
			layer := manV2.Layers[j]
			imageInfo.Layers = append(imageInfo.Layers, string(layer.Digest))
			imageInfo.Sizes[string(layer.Digest)] = layer.Size
			if layer.MediaType != mediaTypeCosign {
				allLayersAreCosignPayloads = false
			}

			j--
		}
	}

	return allLayersAreCosignPayloads
}

func (rc *RegClient) buildV2ImageInfo(imageInfo *ImageInfo, ctx context.Context, name, dg string, body []byte) (parsedSchemaVersion int, err error) {
	var manV2 manifestV2.Manifest

	err = json.Unmarshal(body, &manV2)
	if err != nil {
		return manV2.SchemaVersion, err
	}
	if manV2.SchemaVersion != 2 {
		return manV2.SchemaVersion, fmt.Errorf("unexpected manifest schema version: %d", manV2.SchemaVersion)
	}

	// use v2 config.Digest as repo id
	imageInfo.ID = string(manV2.Config.Digest)
	imageInfo.Digest = dg

	var ccmi *registry.ManifestInfo
	if manV2.Config.MediaType == registry.MediaTypeContainerImage {
		if ccmi, err = rc.ImageConfigSpecV1(ctx, name, manV2.Config.Digest); err == nil {
			imageInfo.Cmds = ccmi.Cmds
			imageInfo.Envs = ccmi.Envs
			imageInfo.Labels = ccmi.Labels
		}
	}

	imageInfo.IsSignatureImage = rc.copyV2LayerAndHistory(imageInfo, &manV2, ccmi)

	log.WithFields(log.Fields{"layers": len(manV2.Layers), "version": manV2.SchemaVersion, "digest": dg, "cmds": len(imageInfo.Cmds)}).Debug("v2 manifest")
	return manV2.SchemaVersion, nil
}

func (rc *RegClient) GetImageInfo(ctx context.Context, name, tag string, manifestReqType registry.ManifestRequestType) (*ImageInfo, share.ScanErrorCode) {
	var dg string
	var body []byte
	var err error
	var isQuaySpecialCase = false

	imageInfo := &ImageInfo{
		Layers: make([]string, 0),
		Envs:   make([]string, 0),
		Cmds:   make([]string, 0),
		Labels: make(map[string]string),
		Sizes:  make(map[string]int64),
	}

	if IsPotentialCosignSignatureTag(tag) && IsQuayRegistry(rc) {
		dg, body, err = rc.ManifestRequest(ctx, name, tag, 2, registry.ManifestRequest_CosignSignature)
		if err == nil {
			_, err = rc.buildV2ImageInfo(imageInfo, ctx, name, dg, body)
			if err == nil {
				isQuaySpecialCase = true
			}
		}
	}

	if !isQuaySpecialCase {
		dg, body, err = rc.ManifestRequest(ctx, name, tag, 2, manifestReqType)

		if err == nil {
			// check if response is manifest list
			var ml manifestList.DeserializedManifestList
			if err = ml.UnmarshalJSON(body); err == nil && len(ml.Manifests) > 0 &&
				(ml.MediaType == manifestList.MediaTypeManifestList || ml.MediaType == registry.MediaTypeOCIIndex) {
				// prefer to scan linux/amd64 image
				sort.Slice(ml.Manifests, func(i, j int) bool {
					if ml.Manifests[i].Platform.OS == "linux" && ml.Manifests[i].Platform.Architecture == "amd64" {
						return true
					} else if ml.Manifests[j].Platform.OS == "linux" && ml.Manifests[j].Platform.Architecture == "amd64" {
						return false
					} else if ml.Manifests[i].Platform.OS == "linux" {
						return true
					} else {
						return false
					}
				})

				tag = string(ml.Manifests[0].Digest)
				dg = tag
				log.WithFields(log.Fields{"os": ml.Manifests[0].Platform.OS, "arch": ml.Manifests[0].Platform.Architecture, "tag": tag}).Debug("manifest list")

				_, body, err = rc.ManifestRequest(ctx, name, tag, 2, manifestReqType)
			}
		}

		// get schema v2 first
		if err == nil {
			var parsedSchemaVersion int
			parsedSchemaVersion, err = rc.buildV2ImageInfo(imageInfo, ctx, name, dg, body)
			if err != nil {
				log.WithFields(log.Fields{"error": err, "schema": parsedSchemaVersion}).Debug("Failed to get manifest schema v2")
			}
		}
	}

	// get schema v1
	manV1, err := rc.Manifest(ctx, name, tag)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Get Manifest v1 fail")
	} else {
		log.WithFields(log.Fields{
			"layers": len(manV1.SignedManifest.FSLayers), "cmds": len(manV1.Cmds), "digest": manV1.Digest,
			"version": manV1.SignedManifest.SchemaVersion,
		}).Debug("v1 manifest request")

		// in Harbor registry, even we send request with accept v1 manifest, we still get v2 format back
		if manV1.SignedManifest.SchemaVersion <= 1 {
			if len(manV1.SignedManifest.FSLayers) > 0 {
				imageInfo.Layers = make([]string, len(manV1.SignedManifest.FSLayers))
				for i, des := range manV1.SignedManifest.FSLayers {
					imageInfo.Layers[i] = string(des.BlobSum)
					// log.WithFields(log.Fields{"i": i, "layer": string(des.BlobSum)}).Debug("v1 manifest")
				}
			}

			// no config in v1, use the latest layer id as the repo id
			if imageInfo.ID == "" {
				imageInfo.ID = rc.getSchemaV1Id(manV1.SignedManifest)
				if imageInfo.ID == "" && len(manV1.SignedManifest.FSLayers) > 0 {
					imageInfo.ID = string(manV1.SignedManifest.FSLayers[0].BlobSum)
				}
			}
			if imageInfo.Digest == "" {
				imageInfo.Digest = manV1.Digest
			}

			// comment out because it's not an accurate way to tell it's signed
			/*if sigs, err := manV1.Signatures(); err == nil && len(sigs) > 0 {
				signed = true
			}*/

			if len(manV1.Envs) > 0 {
				imageInfo.Envs = manV1.Envs
			}
			if len(manV1.Cmds) > 0 {
				imageInfo.Cmds = manV1.Cmds
			}
			if len(manV1.Labels) > 0 {
				imageInfo.Labels = manV1.Labels
			}
			if manV1.Author != "" {
				imageInfo.Author = manV1.Author
			}
		}
	}

	if strings.HasPrefix(imageInfo.ID, "sha") {
		if i := strings.Index(imageInfo.ID, ":"); i > 0 {
			imageInfo.ID = imageInfo.ID[i+1:]
		}
	}
	if imageInfo.ID == "" || len(imageInfo.Layers) == 0 {
		log.WithFields(log.Fields{"imageInfo": imageInfo}).Error("Get metadata fail")
		return imageInfo, share.ScanErrorCode_ScanErrRegistryAPI
	}

	runAsRoot, _, _ := ParseImageCmds(imageInfo.Cmds)
	imageInfo.RunAsRoot = runAsRoot

	imageInfo.RawManifest = body

	return imageInfo, share.ScanErrorCode_ScanErrNone
}

//this function will be called at scanner side
func (rc *RegClient) DownloadRemoteImage(ctx context.Context, name, imgPath string, layers []string, sizes map[string]int64) (map[string]*LayerFiles, share.ScanErrorCode) {
	log.WithFields(log.Fields{"name": name}).Debug()

	// scheme is always set to v1 because layers of v2 image have been reversed in GetImageInfo.
	return getImageLayerIterate(ctx, layers, sizes, true, imgPath, func(ctx context.Context, layer string) (interface{}, int64, error) {
		return rc.DownloadLayer(ctx, name, goDigest.Digest(layer))
	})
}

func (rc *RegClient) getSchemaV1Id(manV1 *manifestV1.SignedManifest) string {
	var id string
	if len(manV1.History) > 0 {
		v1com := manV1.History[0].V1Compatibility
		if i := strings.Index(v1com, "\"id\":\""); i >= 0 {
			v1com = v1com[i+6:]
			if i = strings.Index(v1com, "\""); i > 0 {
				id = v1com[:i]
			}
		}
	}
	return id
}

func (rc *RegClient) Alive() (uint, error) {
	return rc.Ping()
}

// GetCosignSignatureTagFromDigest takes an image digest and returns the default tag
// used by Cosign to store signature data for the given digest.
//
// Example transition
//
// Given Image Digest: sha256:5e9473a466b637e566f32ede17c23d8b2fd7e575765a9ebd5169b9dbc8bb5d16
//
// Resulting Signature Tag: sha256-5e9473a466b637e566f32ede17c23d8b2fd7e575765a9ebd5169b9dbc8bb5d16.sig
func GetCosignSignatureTagFromDigest(digest string) string {
	signatureTag := []rune(digest)
	signatureTag[strings.Index(digest, ":")] = '-'
	return string(signatureTag) + ".sig"
}

// GetSignatureDataForImage fetches the signature image's maniest and layers for the
// given repository and digest. The layers are small JSON blobs that represent the payload created and signed
// by Sigstore's Cosign to be used in verification later.
//
// More information about the cosign's signature specification can be found here:
// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md
func (rc *RegClient) GetSignatureDataForImage(ctx context.Context, repo string, digest string) (s SignatureData, errCode share.ScanErrorCode) {
	signatureTag := GetCosignSignatureTagFromDigest(digest)
	info, errCode := rc.GetImageInfo(ctx, repo, signatureTag, registry.ManifestRequest_CosignSignature)
	if errCode != share.ScanErrorCode_ScanErrNone {
		return SignatureData{}, errCode
	}
	s.Payloads = make(map[string]string)
	for _, layer := range info.Layers {
		rdr, _, err := rc.DownloadLayer(context.Background(), repo, goDigest.Digest(layer))
		if err != nil {
			return SignatureData{}, share.ScanErrorCode_ScanErrRegistryAPI
		}
		layerBytes, err := ioutil.ReadAll(rdr)
		if err != nil {
			return SignatureData{}, share.ScanErrorCode_ScanErrRegistryAPI
		}
		s.Payloads[layer] = string(layerBytes)
	}
	s.Manifest = string(info.RawManifest)
	return s, share.ScanErrorCode_ScanErrNone
}
