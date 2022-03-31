#!/bin/sh

RELEASE=$1 make bci_controller
RELEASE=$1 make bci_enforcer
RELEASE=$1 make bci_manager
RELEASE=latest make bci_scanner

# docker push neuvector/controller.bci:$1
# docker push neuvector/enforcer.bci:$1
# docker push neuvector/manager.bci:$1
# docker push neuvector/scanner.bci:latest
