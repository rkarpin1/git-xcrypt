# Git integration test harness — Plan Brief

> Pełny plan: `context/changes/git-integration-test-harness/plan.md`

## What and why

Budujemy fundament testowy `F-01`: pomocnik stawiający prawdziwe repozytorium git w katalogu
tymczasowym, rejestrujący w nim naszą binarkę jako filtr `clean`/`smudge` i pozwalający odczytać
surowe bajty tego, co git faktycznie zapisał w obiektach. Powód: determinizm szyfrowania i brak
uszkodzeń treści są obserwowalne wyłącznie przez zawartość obiektów gita — ręczne sprawdzenie
tych własności ich nie wychwyci, a opierają na nich swój dowód `S-01`, `S-03`, `S-04` i `S-06`.

## Starting point

`src/main.rs` to hello world, `Cargo.toml` nie ma zależności, katalog `tests/` nie istnieje,
historia liczy jeden commit. Nie ma też podziału `lib` + `bin`, którego wymaga `zalozenia.md`.

## Desired end state

`cargo test` uruchamia zestaw testów na prawdziwych repozytoriach git, dowodzących że: blob
w obiekcie różni się od pliku roboczego, checkout odtwarza treść bajt w bajt przy czystym
`git status`, klon bez filtra pokazuje ciphertext, pliki puste i binarne przechodzą bez
zniekształcenia, a awaria filtra przerywa operację zamiast wpuścić plaintext do indeksu.

## Key decisions made

| Decyzja                            | Wybór                                             | Dlaczego                                                                                  |
| ---------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Co harness napędza                 | Ukryta komenda `__test-filter` w naszej binarce    | Dowód końca-do-końca na własnym pliku wykonywalnym, w tym stdin/stdout i kody wyjścia       |
| Struktura crate'a                  | `lib` + cienki `bin` już teraz                     | Testy integracyjne widzą tylko crate biblioteczny; `S-01` nie zaczyna od refaktoru          |
| Lokalizacja harnessu               | `tests/harness/` jako moduł testów                 | Zero powierzchni w wydanej binarce, `tempfile` zostaje w `dev-dependencies`                 |
| Izolacja środowiska git            | Tylko tożsamość commitera, reszta dziedziczona     | Decyzja użytkownika; ryzyko odnotowane w Open Risks                                         |
| Klon w zakresie `F-01`             | Tak                                                | Jedyny sposób udowodnienia kryterium 5 z PRD; `S-03` dostaje gotowy fundament               |
| Zakres platform                    | Kod przenośny, CI w `S-07`                         | Przenośność kosztuje najmniej wpisana od początku, ale pipeline należy do innego elementu   |
| Kształt API asercji                | Surowe bajty + kilka cienkich asercji              | „Zaszyfrowany" nie jest jeszcze zdefiniowany; asercja wysokopoziomowa musiałaby zgadywać format |

## Scope

**W zakresie:** podział `lib`/`bin`, komenda `__test-filter`, fabryka repozytorium testowego,
rejestracja filtra z `required = true`, commit, klon, odczyt bajtów bloba, cienkie asercje,
testy: różnica blob/plik roboczy, round-trip, czysty `status`, plik pusty, plik binarny,
awaria filtra.

**Poza zakresem:** kryptografia, format pliku, prawdziwe komendy CLI, biblioteka do argumentów,
zarządzanie kluczem, plik `.git-crypt`, generowanie `.gitattributes`, CI, poprawka `zalozenia.md`.

## Approach

Binarka wystawia jedną ukrytą komendę odwracającą bajty — transformacja jest odwracalna,
deterministyczna i sama sobie odwrotna, więc obsługuje `clean` i `smudge` naraz. `S-01`
podmienia jej wnętrze na AES-256-SIV, nie ruszając harnessu. Moduł `tests/harness/` woła
prawdziwego `git` jako podproces i zwraca `Vec<u8>` — cała ścieżka odczytu jest bajtowa,
bo ciphertext nie jest poprawnym UTF-8.

## Phases at a glance

| Faza                                  | Co dostarcza                                                     | Kluczowe ryzyko                                                              |
| ------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| 1. Podział crate'a i `__test-filter`  | Obiekt, który git może uruchomić jako filtr                       | Kod testowy w binarce produkcyjnej — `S-01` musi go usunąć                    |
| 2. Harness: repo, filtr, odczyt bloba | Pionowy przekrój z testem „blob ≠ plik roboczy"                   | Cytowanie ścieżki filtra; git uruchamia polecenie przez powłokę               |
| 3. Klon, asercje, przypadki brzegowe  | Klon, cienkie asercje, sześć testów brzegowych                    | Test awarii filtra jest jedynym strażnikiem flagi `required`                  |

**Wymagania wstępne:** `git` w `PATH` (2.x), toolchain Rust z edycją 2024. Oba obecne.
**Szacowany nakład pracy:** ~2-3 sesje, po jednej na fazę.

## Open risks and assumptions

- Globalna konfiguracja gita nie jest izolowana — `core.autocrlf` i globalny `.gitattributes`
  z maszyny mogą przebić się do wyniku i objawić jako fałszywa regresja determinizmu w `S-01`.
- `zalozenia.md` §Integracja z git twierdzi, że git przerywa operację przy niezerowym kodzie
  filtra. Sonda na git 2.55.0 pokazała, że jest to prawda **wyłącznie** z `filter.<nazwa>.required = true`;
  bez niej `git add` kończy się kodem 0 i commituje plaintext. Dokument wymaga poprawki przed `S-01`.
- `__test-filter` zostaje w binarce do czasu `S-01`.
- Przenośność jest zadeklarowana w kodzie, ale sprawdzona wyłącznie na macOS.

## Success criteria (summary)

- `cargo test` zielone, `cargo clippy --all-targets -- -D warnings` i `cargo fmt --check` czyste.
- Świadome zepsucie transformacji daje czerwony test — dowód, że testy faktycznie sprawdzają treść.
- Usunięcie `required = true` daje czerwony test — dowód, że gwarantka „awaria przerywa operację"
  jest pilnowana, a nie zakładana.
