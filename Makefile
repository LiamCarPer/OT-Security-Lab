LAB = lab-environment

.PHONY: up down ps simulate simulate-lateral simulate-process ids-log compliance test lint scan

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

test:
	python3 -m pytest tests -q

lint:
	ruff check detection automation governance tests
	bandit -q -r detection automation governance -x governance/testing

scan:
	pip-audit -r requirements-dev.txt
