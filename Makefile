LAB = lab-environment

.PHONY: up down ps simulate simulate-lateral simulate-process ids-log compliance historian test lint scan powershell-test powershell-lint powershell-report caldera caldera-image caldera-down

up:
	cd $(LAB) && docker compose up -d

down:
	cd $(LAB) && docker compose down

ps:
	cd $(LAB) && docker compose ps

simulate:
	docker exec ot_attacker python3 /attacker/simulate_attack.py

simulate-lateral:
	docker exec ot_attacker python3 /attacker/simulate_lateral_movement.py

simulate-process:
	docker exec ot_attacker python3 /attacker/simulate_process_violation.py

ids-log:
	docker exec ot_gateway sh -c "cat /detection/logs/*.out"

compliance:
	python3 governance/testing/run_security_tests.py --reset

historian:
	python3 governance/testing/check_historian.py

test:
	python3 -m pytest tests -q

lint:
	ruff check detection automation governance tests plc lab-environment
	bandit -q -r detection automation governance -x governance/testing

scan:
	pip-audit -r requirements-dev.txt

policy:
	conftest test -p tests/policy lab-environment/docker-compose.yml

precommit:
	pre-commit run --all-files

powershell-test:
	pwsh -NoProfile -Command "Invoke-Pester -Path tests/powershell -Output Detailed -CI"

powershell-lint:
	pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path powershell -Recurse -Settings powershell/PSScriptAnalyzerSettings.psd1 -EnableExit"

powershell-report:
	pwsh -NoProfile -File powershell/Get-OTDetectionReport.ps1 -AsMarkdown -OutputPath evidence/powershell-coverage.md

caldera-image:
	cd $(LAB) && sh caldera/build.sh

caldera:
	@docker image inspect $${OT_CALDERA_IMAGE:-ot-caldera:5.3.0} >/dev/null 2>&1 || $(MAKE) caldera-image
	cd $(LAB) && CALDERA_URL=http://caldera:8888 docker compose --profile caldera up -d

caldera-down:
	cd $(LAB) && docker compose stop caldera
