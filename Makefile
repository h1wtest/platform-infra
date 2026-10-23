PYTHON ?= uv run --no-project python
PLATFORM = $(PYTHON) scripts/cli.py
shell_quote = '$(subst ','"'"',$(1))'
.PHONY: bootstrap build up check status stop start cluster-identity bootstrap-admin schedule-backups backup restore-verify schema-gate repair-certificates rekey chaos persistence alerts mailpit prometheus grafana tempo test acceptance host-fault helm-adopt releases release release-rollback
bootstrap:
	$(PLATFORM) secrets
build:
	$(PLATFORM) build
up:
	$(PLATFORM) up
helm-adopt:
	$(PLATFORM) helm-adopt
releases:
	$(PLATFORM) releases
release:
	$(PLATFORM) release --service $(call shell_quote,$(SERVICE)) --image $(call shell_quote,$(IMAGE)) --probe $(call shell_quote,$(PROBE)) $(if $(TIMEOUT),--timeout $(call shell_quote,$(TIMEOUT)),)
release-rollback:
	$(PLATFORM) release-rollback --service $(call shell_quote,$(SERVICE)) --revision $(call shell_quote,$(REVISION)) --probe $(call shell_quote,$(PROBE)) $(if $(TIMEOUT),--timeout $(call shell_quote,$(TIMEOUT)),)
check:
	$(PLATFORM) check
status:
	$(PLATFORM) status
stop:
	$(PLATFORM) stop
start:
	$(PLATFORM) start
cluster-identity:
	$(PLATFORM) cluster-identity
bootstrap-admin:
	$(PLATFORM) bootstrap-admin
schedule-backups:
	$(PLATFORM) schedule-backups
backup:
	$(PLATFORM) backup
restore-verify:
	$(PLATFORM) restore-verify --backup $(call shell_quote,$(BACKUP))
schema-gate:
	$(PLATFORM) schema-gate
repair-certificates:
	$(PLATFORM) repair-certificates
rekey:
	$(PLATFORM) rekey $(ARGS)
chaos:
	$(PLATFORM) chaos --target $(call shell_quote,$(or $(TARGET),identity-service)) --probe $(call shell_quote,$(PROBE))
persistence:
	$(PLATFORM) persistence
alerts:
	$(PLATFORM) alerts
mailpit prometheus grafana tempo:
	$(PLATFORM) $@
test:
	$(PYTHON) -m unittest discover -s scripts/tests -p 'test_*.py'
acceptance:
	$(PYTHON) scripts/acceptance/run.py $(call shell_quote,$(or $(GATE),core)) $(ARGS)
.PHONY: benchmark-registration
benchmark-registration:
	$(PYTHON) scripts/acceptance/registration_benchmark.py $(ARGS)
host-fault:
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$$(wslpath -w $(call shell_quote,$(CURDIR)/scripts/verify-docker-host.ps1))" -Repository $(call shell_quote,$(CURDIR)) $(if $(filter 1,$(ALLOW_SHARED_HOST_OUTAGE)),-AllowSharedHostOutage,)
