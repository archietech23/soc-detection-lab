# SOC Detection Lab — deployment + validation
#
# Usage:
#   make validate   # lint detection cards and Splunk .conf
#   make deploy     # copy the Splunk app into $SPLUNK_HOME/etc/apps and restart
#   make diff       # show what would change on the Splunk host
#
# Override the Splunk install path if not /opt/splunk:
#   make deploy SPLUNK_HOME=/opt/splunk

SPLUNK_HOME ?= /opt/splunk
APP_NAME    := soc_detection_lab
APP_SRC     := splunk-app/$(APP_NAME)
APP_DEST    := $(SPLUNK_HOME)/etc/apps/$(APP_NAME)

.PHONY: validate deploy diff restart help

help:
	@echo "make validate  - lint detection cards and savedsearches.conf"
	@echo "make deploy    - deploy app to $(APP_DEST) and restart Splunk"
	@echo "make diff      - show what would change on the Splunk host"

validate:
	@bash tests/lint-detections.sh

diff:
	@if [ -d "$(APP_DEST)" ]; then \
		diff -r "$(APP_SRC)" "$(APP_DEST)" || true ; \
	else \
		echo "App not yet deployed to $(APP_DEST)"; \
	fi

deploy: validate
	@echo ">>> Deploying $(APP_NAME) to $(APP_DEST)"
	sudo mkdir -p $(SPLUNK_HOME)/etc/apps
	sudo rm -rf $(APP_DEST)
	sudo cp -r $(APP_SRC) $(APP_DEST)
	sudo chown -R splunk:splunk $(APP_DEST) 2>/dev/null || true
	@$(MAKE) restart

restart:
	@echo ">>> Restarting Splunk"
	sudo $(SPLUNK_HOME)/bin/splunk restart
