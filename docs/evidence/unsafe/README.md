# Небезопасный код: журналы

Что и почему — `docs/UNSAFE.md`.

* `before-fix.log` — каждое исправление коммита `2197e9e` откачено по
  очереди, тест, который за него стоит, прогнан в отладочной сборке и под
  Miri: старое чтение адресов по ссылке останавливает и то и другое
  («misaligned pointer dereference», «unaligned reference»), старый пустой
  ответ DPAPI — Miri, исполняющий код для Windows («null reference»).
  Закоммиченный код проходит всё.
* `miri.log` — `scripts/miri.sh` на `2197e9e`.
* `miri-modules.log` — модули без вызовов в систему под Miri: `protocol`
  чисто за девять минут; `crypto::transport` остановлен, не закончив за
  восемь.

```
sh scripts/miri.sh      # nightly с компонентами miri и rust-src
```
