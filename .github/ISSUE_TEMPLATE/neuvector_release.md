---
name: NeuVector Release
about: Issue with all the items needed to release a new version of NeuVector
title: "NeuVector <VERSION> release"
labels: ''
assignees: ''
projects: ["neuvector/15"]

---

### Checklist

This issue tracks the release of a new version of NeuVector. Please
follow the checklist below to ensure a smooth release process.
(ref: https://confluence.suse.com/spaces/NeuVector/pages/1335722612/NeuVector+Release+Check+List)

- [ ] Is documentation ready to be published?
  - [ ] CVEs (if applicable)
  - [ ] Release note
  - [ ] New version
  - [ ] Matrix
  - [ ] Tech Writer notified
- [ ] Images are updated and available
- [ ] No cve is found scanned by trivy, ms and our scanner tool on released images.
- [ ] Pass the release test suites.
- [ ] Release Notes.
- [ ] REST API document checked-in.NA
- [ ] Helm charts branch created and tagged.
- [ ] Add new supported apis in support log.
- [ ] Load release build in long run setup.
- [ ] OpenShift Operator. (Esther)
- [ ] Rancher feature chart PR submitted and merged. (Leo)
- [ ] Publish UBI. (Esther)
- [ ] Announce neuvector-updates email list. (William)
- [ ] CRD changes document.
- [ ] Publish Documentation. (need to update support matrix and features.)
- [ ] Verify https://open-docs.neuvector.com/releasenotes/5x/ is up-to-date

