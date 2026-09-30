# Цепочка поставок: журналы

Что сделано и почему — `docs/SUPPLY_CHAIN.md`.

* `audit-before.log` — cargo-audit по `Cargo.lock` коммита `27d3cd4`, до
  этой работы, без списка исключений: 4 уязвимости (`bytes`,
  `crossbeam-epoch`, `tracing-subscriber`, `webbrowser`) и 9 предупреждений
  (брошенные крейты GUI; небезопасный код в `anyhow`, `rand`, `memmap2`
  обеих версий, `event-listener`).
* `supply-chain.log` — `scripts/supply-chain.sh` после: cargo-deny (всё,
  затем дубли без GUI), cargo-audit (крейт и `fuzz/`), cargo-vet.
  Предупреждения cargo-audit — пять исключений из `deny.toml`: сам он
  падает только на уязвимостях.
* `deps.log` — сколько крейтов в каждой сборке до и после.
* `repro-headless.log`, `repro-gui.log` — `scripts/repro.sh check`: две
  сборки, различающиеся всем, кроме исходника и образа, дали одинаковые
  бинарники.
* `repro-control-without-remap.log` — контроль: та же проверка без
  приведения путей (`--remap-path-prefix`) находит различие.

```
sh scripts/supply-chain.sh
sh scripts/repro.sh check                       # без GUI
REPRO_VARIANT=gui sh scripts/repro.sh check     # с GUI
```
