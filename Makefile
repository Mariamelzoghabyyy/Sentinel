.PHONY: demo test samples clean bench judge datasets

demo:            ## run the mixed-traffic sample with auto-approval
	python3 -m sentinel samples/access.log --approve-all --out reports/access_report.md

demo-interactive: ## walk through the human approval gate yourself
	python3 -m sentinel samples/access.log --interactive --out reports/access_report.md

incident:        ## the P1 storm scenario
	python3 -m sentinel samples/incident.log --approve-all --out reports/incident_report.md

test:            ## full suite
	python3 -m pytest tests/ -q

samples:         ## regenerate synthetic logs
	python3 scripts/make_samples.py

clean:
	rm -rf reports/*.md __pycache__ */__pycache__ .pytest_cache

bench:           ## rules-only baseline on the 22 labelled cases
	python3 benchmark/evaluate.py

judge:           ## LLM-as-judge (abstains cleanly without a backend)
	python3 benchmark/judge_eval.py --repeat 3

datasets:        ## list the public-dataset converters
	python3 -m benchmark.adapters --list
