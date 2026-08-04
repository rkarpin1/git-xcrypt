<!-- IMPL-REVIEW-REPORT -->
# Implementation Review: Git integration test harness

- **Plan**: `context/changes/git-integration-test-harness/plan.md`
- **Scope**: Phases 1–3 of 3
- **Date**: 2026-08-04
- **Verdict**: NEEDS ATTENTION (all findings resolved during triage)
- **Findings**: 0 critical, 2 warnings, 4 observations

## Verdicts

| Dimension           | Verdict |
| ------------------- | ------- |
| Plan Adherence      | WARNING |
| Scope Discipline    | PASS    |
| Safety & Quality    | WARNING |
| Architecture        | PASS    |
| Pattern Consistency | WARNING |
| Success Criteria    | PASS    |

Kryteria automatyczne wszystkich trzech faz przechodzą: `cargo build`, `cargo test`
(12 testów), `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
`cargo audit` (20 zależności, kod wyjścia 0). Weryfikacje ręczne mają dowody w sesji —
zepsucie transformacji i usunięcie `required = true` faktycznie dawały czerwień, więc
nie ma podpisów na ślepo. Jedyne kryterium niezaznaczone (3.7, druga platforma) było
w planie oznaczone jako nieblokujące.

## Findings

### F1 — Probe file puts plaintext in the working tree

- **Severity**: ⚠️ WARNING
- **Impact**: 🏃 LOW — szybka decyzja; poprawka jest wąska
- **Dimension**: Safety & Quality
- **Location**: `tests/harness/mod.rs:110-120` (przed poprawką)
- **Detail**: `object_exists_for` zapisywało badaną treść do pliku
  `.git-xcrypt-plaintext-probe` wewnątrz drzewa roboczego repozytorium testowego, tylko po
  to, żeby policzyć jej hash. Sprzątanie następowało po `git_ok`, który panikuje przy
  niepowodzeniu, więc panika zostawiłaby plik z plaintextem w drzewie roboczym — a
  `commit_all` używa `git add -A`, więc kolejny commit w tym samym teście by go
  zacommitował. Dotyka twardej reguły z `AGENTS.md` („Never commit a key or a secret.
  Tests and examples included").
- **Fix**: Hash liczony przez `git hash-object -t blob --stdin`, treść podawana na stdin.
  Dodany `git_with_stdin` jako wariant `git()` obsługujący potok wejściowy.
  - Strength: usuwa okno wycieku całkowicie, a nie skraca je.
  - Trade-off: ~20 linii nowego pomocnika w harnessie.
  - Confidence: HIGH — po zmianie powtórzono test negatywny (usunięcie
    `required = true` nadal wywala oba testy awarii), więc asercja nie straciła mocy.
  - Blind spot: brak.
- **Decision**: FIXED

### F2 — AGENTS.md §Testing zaprzecza stanowi repozytorium

- **Severity**: ⚠️ WARNING
- **Impact**: 🏃 LOW — szybka decyzja; poprawka jest wąska
- **Dimension**: Pattern Consistency
- **Location**: `AGENTS.md:36`
- **Detail**: „`tests/` does not exist yet" — nieprawda od commita `040f71e`. Plik jest
  czytany przez każdego agenta na starcie sesji, więc fałsz w nim kosztuje więcej niż
  w dokumencie, po który sięga się świadomie.
- **Fix**: Zdanie zastąpione opisem stanu faktycznego: harness w `tests/harness/mod.rs`,
  wpinany przez `mod harness;`. Reszta akapitu bez zmian, bo była aktualna.
- **Decision**: FIXED

### F3 — Test 6 użyto innego mechanizmu niż w planie

- **Severity**: 📝 OBSERVATION
- **Impact**: 🏃 LOW
- **Dimension**: Plan Adherence
- **Location**: `tests/harness/mod.rs:110-126`
- **Detail**: Plan zapowiadał `git cat-file --batch-all-objects --batch-check`;
  implementacja liczy hash i sprawdza `git cat-file -e`. Prostsze i równoważne, ale plan
  opisywał coś, czego w kodzie nie ma.
- **Fix**: Zaktualizowano kontrakt fazy 3 w planie, żeby opisywał faktyczny mechanizm
  wraz z uzasadnieniem użycia stdin.
- **Decision**: FIXED

### F4 — Nieplanowany drugi test w fazie 2

- **Severity**: 📝 OBSERVATION
- **Impact**: 🏃 LOW
- **Dimension**: Plan Adherence
- **Location**: `tests/filter_pipeline.rs:24`
- **Detail**: `unmatched_files_are_stored_verbatim` nie był w planie — faza 2 przewidywała
  jeden test dowodowy. Test sprawdza sensowną rzecz: bez niego pierwszy test przechodziłby
  również wtedy, gdyby filtr działał na wszystkich plikach zamiast na objętych wzorcem.
- **Fix**: Dopisany do kontraktu fazy 2 w planie razem z uzasadnieniem.
- **Decision**: FIXED

### F5 — Ścieżka filtra cytowana, ale nieescapowana

- **Severity**: 📝 OBSERVATION
- **Impact**: 🏃 LOW
- **Dimension**: Pattern Consistency
- **Location**: `tests/harness/mod.rs:262-268` (przed poprawką)
- **Detail**: `filter_command` owijało ścieżkę w cudzysłów i zamieniało `\` na `/`, ale nie
  escapowało `"`, `$` ani backticka. Git przekazuje wartość powłoce, więc katalog projektu
  zawierający `$` rozsypałby polecenie. Mało prawdopodobne, ale to kod pisany właśnie pod
  przenośność.
- **Fix**: Cytowanie pojedyncze zamiast podwójnego — wewnątrz apostrofów powłoka POSIX nie
  rozwija niczego. Literalny apostrof zamykany, escapowany i otwierany ponownie. Zamiana
  `\` na `/` wykonywana jako pierwsza, żeby nie zjadła wprowadzonego escape'u.
- **Decision**: FIXED

### F6 — Roadmapa nie wie, że F-01 jest zrobione

- **Severity**: 📝 OBSERVATION
- **Impact**: 🏃 LOW
- **Dimension**: Plan Adherence
- **Location**: `context/foundation/roadmap.md`
- **Detail**: Status F-01 to nadal `ready`, a `change.md` mówi `implemented`.
- **Fix**: Domyka `/10x-archive git-integration-test-harness`, które przestawia status na
  `done`, dopisuje wpis w `## Done` i przenosi folder zmiany do `context/archive/`.
  Ręczna edycja samego statusu pozostawiłaby folder na miejscu i rozjechała się z tym,
  czego oczekuje umiejętność archiwizująca.
- **Decision**: PENDING — wymaga uruchomienia `/10x-archive`
