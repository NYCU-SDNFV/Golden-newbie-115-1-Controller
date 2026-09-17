# Lab 1 -- SDN: OVS + your own OpenFlow controller
# Do not modify this file.

COMPOSE   ?= docker compose
CONTAINER ?= lab1
MODE      ?= controller

.NOTPARALLEL:
.PHONY: all build up down policy check-update update test test-offline a0 a1 a2 a3 a4 report b c hold shell logs clean

all: up test

build:
	$(COMPOSE) build

up:
	$(COMPOSE) up -d --build
	@echo "waiting for $(CONTAINER) to be ready ..."
	@sh tests/wait_ready.sh

down:
	-$(COMPOSE) down --remove-orphans

policy:
	@bash .github/policy/00_layout.sh
	@bash .github/policy/01_integrity.sh

check-update:
	@python3 .github/release/upgrade.py check

update:
	@python3 .github/release/upgrade.py update

test: check-update
	@$(MAKE) test-offline

# Explicit offline verification only; never claims release freshness.
test-offline: policy
	@sh tests/00_env.sh
	@sh tests/05_a0_reference.sh
	@sh tests/10_a1_flood.sh
	@sh tests/20_a2_normal.sh
	@sh tests/30_a3a_handshake.sh
	@sh tests/31_a3b_packet_in.sh
	@sh tests/32_a3c_flow_mod.sh
	@sh tests/33_a3d_learning.sh
	@sh tests/40_a4_proactive.sh
	@sh tests/50_b_ring.sh
	@sh tests/51_b_ring11.sh
	@sh tests/60_git.sh
	@sh tests/70_report.sh
	@echo ""
	@echo "All Lab 1 checks passed."

# One part at a time while you work.
a0: ; @sh tests/05_a0_reference.sh
a1: ; @sh tests/10_a1_flood.sh
a2: ; @sh tests/20_a2_normal.sh
a3: ; @sh tests/30_a3a_handshake.sh && sh tests/31_a3b_packet_in.sh && sh tests/32_a3c_flow_mod.sh && sh tests/33_a3d_learning.sh
a4: ; @sh tests/40_a4_proactive.sh
report: ; @sh tests/70_report.sh
c: report
b: ; @sh tests/50_b_ring.sh && sh tests/51_b_ring11.sh

# Bring a mode up and stay in the Mininet CLI (used at the checkpoint):
#   make hold MODE=controller
hold:
	docker exec -it $(CONTAINER) python3 harness/run_mode.py $(MODE) --hold

shell:
	docker exec -it $(CONTAINER) bash

logs:
	-$(COMPOSE) ps
	-$(COMPOSE) logs --no-color --tail=200

clean:
	-docker exec $(CONTAINER) mn -c
	-$(COMPOSE) down -v --remove-orphans
	-rm -rf results captures
