---
bootstrapped_at: 2026-08-03T19:54:22Z
starter_id: rust
starter_name: "Rust (binary crate)"
project_name: git-crypt
language_family: rust
package_manager: cargo
cwd_strategy: subdir-then-move
bootstrapper_confidence: verified
phase_3_status: ok
audit_command: "cargo audit"
---

## Hand-off

Skopiowane dosłownie z `context/foundation/tech-stack.md`.

```yaml
starter_id: rust
package_manager: cargo
project_name: git-crypt
hints:
  language_family: rust
  team_size: solo
  deployment_target: self-host
  ci_provider: github-actions
  ci_default_flow: manual-promotion
  bootstrapper_confidence: verified
  path_taken: standard
  quality_override: false
  self_check_answers: null
  has_auth: false
  has_payments: false
  has_realtime: false
  has_ai: false
  has_background_jobs: false
```

**Why this stack** (dosłownie z ciała przekazania):

Pojedynczy deweloper budujący narzędzie wiersza poleceń do szyfrowania plików w repozytorium git, w 6 tygodni pracy po godzinach. `rust` jest sprawdzoną rekomendacją dla pary `(cli, rust)` i przechodzi wszystkie cztery bramki przyjazności dla agenta: jawne typy, konwencje `cargo`, silna obecność w danych treningowych i aktualna dokumentacja. Pewność scaffoldowania to `verified`, więc inicjacja przebiegnie bez tarcia — tym bardziej, że katalog zawiera już crate binarny z edycją 2024, dokładnie taki, jaki wygenerowałby starter. Wymóg samowystarczalnej binarki bez zewnętrznych bibliotek (FR-011) i deterministycznego szyfrowania czyni Rust naturalnym wyborem, a nie kompromisem. Cel wdrożenia to `self-host` — produkt nie ma komponentu serwerowego, użytkownik instaluje binarkę u siebie. CI na GitHub Actions z wydaniem sterowanym ręcznie zamiast automatycznego przy merge: dla dystrybuowanej binarki publikowanie release'u przy każdej zmianie w `main` byłoby błędem. Żadna z pięciu funkcji wymuszających technologię (logowanie, płatności, czas rzeczywisty, AI, zadania w tle) nie występuje w tym produkcie.

## Pre-scaffold verification

| Sygnał        | Wartość        | Ważność | Uwagi                                                                          |
| ------------- | -------------- | ------- | ------------------------------------------------------------------------------ |
| pakiet npm    | nie uruchomiono | n/d     | starter spoza rodziny JS; `cmd_template` nie wywołuje CLI z npm                 |
| repozytorium GitHub | nie uruchomiono | n/d | `docs_url` karty to `https://doc.rust-lang.org/book/` — nie jest adresem GitHub; `gh` nie jest zainstalowane |

Brak dostępnego sygnału świeżości. Zgodnie z procedurą jest to ostrzeżenie bez blokady.

## Scaffold log

**Resolved invocation**: `cargo new .bootstrap-scaffold --bin --edition 2024`
**Strategy**: subdir-then-move
**Exit code**: nie wykonano — krok pominięty świadomą decyzją użytkownika
**Files moved**: 0
**Conflicts (.scaffold siblings)**: none
**.gitignore handling**: nietknięty
**.bootstrap-scaffold cleanup**: katalog nigdy nie powstał

### Powód pominięcia

Dwa niezależne ustalenia, oba zweryfikowane przed podjęciem decyzji:

1. **Dosłowne polecenie startera zakończyłoby się błędem.** Przetestowane w katalogu tymczasowym:

   ```
   error: invalid character `.` in package name: `.bootstrap-scaffold`,
   the first character must be a Unicode XID start character
   note: the directory name is used as the package name
   EXIT=101
   ```

   `cargo` wyprowadza nazwę pakietu z nazwy katalogu, a strategia `subdir-then-move` podstawia `{name}=.bootstrap-scaffold`. Zgodnie z procedurą byłby to twardy stop i dziennik ze statusem `failed`. Jest to ograniczenie mechaniki podstawiania w zetknięciu z `cargo new`, nie błąd w karcie startera ani w przekazaniu — warto zgłosić przy aktualizacji `bootstrapper-config.yaml` (obejściem jest dopisanie `--name {project_name}` do `cmd_template` karty `rust`).

2. **Katalog roboczy już odpowiada wynikowi startera.** Stan sprzed uruchomienia:

   | element | stan w katalogu | wynik `cargo new git-crypt --bin --edition 2024` |
   | --- | --- | --- |
   | `Cargo.toml` | `name = "git-crypt"`, `version = "0.1.0"`, `edition = "2024"`, brak zależności | identyczny |
   | `src/main.rs` | `fn main() { println!("Hello, world!"); }` | identyczny |
   | `.gitignore` | `/target` oraz dopisane przez użytkownika `/.idea`, `/.idea/` | `/target` |
   | `Cargo.lock` | obecny | obecny |

   Scaffolding wyprodukowałby wyłącznie pliki `Cargo.toml.scaffold` i `src/main.rs.scaffold` o treści identycznej z istniejącymi.

Użytkownikowi przedstawiono trzy opcje (pominięcie, obejście przez `--name git-crypt`, wykonanie dosłowne z udokumentowaną porażką). Wybrał pominięcie.

## Post-scaffold audit

**Tool**: `cargo audit`
**Summary**: 0 CRITICAL, 0 HIGH, 0 MODERATE, 0 LOW
**Direct vs transitive**: nie dotyczy — projekt nie ma jeszcze żadnej zależności

Surowe wyjście:

```
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 1186 security advisories (from /Users/robertk/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (1 crate dependencies)
EXIT=0
```

Skanowana była jedna pozycja — sam crate `git-crypt`. Wynik jest prawdziwy, ale bez wartości informacyjnej: `Cargo.toml` nie deklaruje jeszcze żadnej zależności. Audyt nabierze znaczenia po dodaniu bibliotek kryptograficznych i warto go wtedy powtórzyć.

## Hints recorded but not acted on

| Hint                    | Wartość              |
| ----------------------- | -------------------- |
| bootstrapper_confidence | verified             |
| quality_override        | false                |
| path_taken              | standard             |
| self_check_answers      | null                 |
| team_size               | solo                 |
| deployment_target       | self-host            |
| ci_provider             | github-actions       |
| ci_default_flow         | manual-promotion     |
| has_auth                | false                |
| has_payments            | false                |
| has_realtime            | false                |
| has_ai                  | false                |
| has_background_jobs     | false                |

Żadna z tych wartości nie wpłynęła na przebieg tego uruchomienia. `ci_provider` i `ci_default_flow` są zapisane, ale bootstrapper w wersji v1 nie generuje plików CI — mimo że FR-011 wprost tego wymaga. To praca do wykonania osobno.

## Next steps

Następnie: przyszła umiejętność skonfiguruje kontekst agenta (`CLAUDE.md`, `AGENTS.md`). Na razie projekt jest zweryfikowany.

Przydatne kroki ręczne w międzyczasie:

- Repozytorium git już istnieje, ale nie ma jeszcze żadnego commita — warto zacommitować stan wyjściowy razem z katalogiem `context/`.
- Brak plików `.scaffold` do przejrzenia — polityka konfliktów nie została uruchomiona.
- Brak znalezisk audytu do rozpatrzenia. Powtórzyć `cargo audit` po dodaniu pierwszych zależności.
- Przed planowaniem implementacji rozstrzygnąć otwarte pytanie nr 1 z PRD (rozjazd `.git-crypt` ↔ `.gitattributes`), oznaczone jako blokujące.
