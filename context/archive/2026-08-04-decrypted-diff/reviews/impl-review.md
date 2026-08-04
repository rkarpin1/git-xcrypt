<!-- IMPL-REVIEW-REPORT -->
# Przegląd implementacji: Różnice na treści odszyfrowanej

- **Plan**: `context/archive/2026-08-04-decrypted-diff/plan.md`
- **Zakres**: Faza 1 z 1 (ukończona)
- **Data**: 2026-08-04
- **Werdykt**: WYMAGA UWAGI po pierwszym przebiegu → ODRZUCONY po drugim → ZAAKCEPTOWANY
- **Ustalenia**: przebieg 1 — 3 ostrzeżenia (dwa o wadze krytycznej dla reguł
  projektu), 6 obserwacji; przebieg 2 — 2 krytyczne, 1 ostrzeżenie, 6 obserwacji
- **Przebiegi**: dwa. Drugi znalazł **dwie luki w naprawach z pierwszego** — obie
  w zabezpieczeniach, które pierwszy przebieg uznał za zamknięte.

## Werdykty

| Wymiar | Przed naprawą | Po naprawie |
| --- | --- | --- |
| Zgodność z planem | PASS | PASS |
| Dyscyplina zakresu | WARNING | PASS |
| Bezpieczeństwo i jakość | FAIL | PASS |
| Architektura | PASS | PASS |
| Spójność wzorców | PASS | PASS |
| Kryteria sukcesu | PASS | PASS |

Bramka jakości po naprawach: `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings` i `cargo test` (232 testy jednostkowe
+ 90 integracyjnych) przechodzą.

## Rozstrzygnięcie, które podważyło założenie planu

Zanim ustalenia: plan zakładał, że `textconv` dostaje ciphertext. **Nie dostaje.**
Zmierzone na git 2.55 przez podstawienie skryptu-loggera w miejsce sterownika: git
materializuje każdą stronę różnicy przez `convert_to_working_tree` (smudge) *zanim*
poda ją sterownikowi, a stronę roboczą pożycza wprost. Sterownik widzi więc
plaintext w obu przypadkach. To, co daje sama rejestracja, to porównanie treści
jako tekstu zamiast `Binary files differ` na surowym ciphertexcie — i to wystarcza,
żeby FR-006 był spełniony. Gałąź deszyfrująca jest zabezpieczeniem, osiągalnym gdy
filtr nie jest zarejestrowany, i ma własny test przez gita
(`ciphertext_reaches_the_driver_when_no_filter_stands_in_front_of_it`).

Konsekwencja weszła do implementacji: **`lock` musi wyrejestrować sterownik**,
inaczej w repozytorium bez klucza textconv wciąga niedziałający smudge i
`fatal: smudge filter git-xcrypt failed` zabija `git log -p` dla każdej
zadeklarowanej ścieżki. Pozostałe rozbieżności wobec planu: `change.md`.

## Przebieg 1

### F1 — plik o nazwie `--help` kazał gitowi pokazać tekst pomocy jako treść

- **Ważność**: ⚠️ OSTRZEŻENIE (w skutkach krytyczne) · **Wymiar**: Bezpieczeństwo i jakość
- **Lokalizacja**: `src/main.rs` (przed naprawą)
- **Szczegóły**: git podaje ścieżkę **względną repozytorium, bez `./` z przodu**, więc
  sterownik dostaje `git-xcrypt diff --help`. Zmierzone: clap wypisywał usage na
  **`stdout`** z kodem **0**, a git renderował to jako treść pliku — bez błędu,
  bez sygnału. Jedyna znaleziona droga, którą na `stdout` sterownika trafia coś,
  co nie jest plikiem: reguła fail-closed odwrócona. Osobno plik `-w.env`
  przerywał `git diff` w całości (`unexpected argument '-w'`, kod 128) — dokładnie
  ta awaria, przed którą chroni wyrejestrowanie sterownika przy `lock`, tyle że
  osiągalna samą nazwą pliku w odblokowanym repozytorium.
- **Naprawa**: `#[arg(allow_hyphen_values = true)]` na ścieżce i
  `#[command(disable_help_flag = true)]` na podkomendzie. `git-xcrypt help diff`
  nadal działa, pozostałe podkomendy zachowują swoje `--help`.
- **Test**: `a_file_named_like_an_option_is_still_a_file` — dwa pliki, `--help`
  i `-w.env`, przez prawdziwy `git diff`.
- **Decyzja**: NAPRAWIONE

### F2 — `git-xcrypt diff` wypisywał klucz główny na `stdout`

- **Ważność**: ⚠️ OSTRZEŻENIE (naruszenie twardej reguły) · **Wymiar**: Bezpieczeństwo i jakość
- **Lokalizacja**: `src/commands/diff.rs` (przed naprawą)
- **Szczegóły**: plik klucza ma magic `\0GITXCRYPTKEY\0`, o jeden bajt inne niż magic
  danych, więc `looks_encrypted` mówi „nie" i klucz szedł gałęzią przepuszczającą.
  Zmierzone: `git-xcrypt diff .git/git-xcrypt/keys/default > stolen.bin` dawało plik
  identyczny z kluczem, w drzewie roboczym, jeden `git add -A` od commita. To jest
  scenariusz, którego `export_key::refuse_bad_destination` odmawia ręcznie, i twarda
  reguła z AGENTS.md.
- **Naprawa**: `refuse_private_path` — odmowa dla ścieżki wewnątrz katalogu gita
  (i wspólnego), z rozwiązywaniem dowiązań przez `canonicalize`. **Niewystarczająca
  — patrz C2 w przebiegu 2.**
- **Decyzja**: NAPRAWIONE, potem poprawione ponownie

### F3 — każdy zdrowy `lock` twierdził, że naprawił zepsutą rejestrację

- **Ważność**: ⚠️ OSTRZEŻENIE · **Wymiar**: Bezpieczeństwo i jakość
- **Lokalizacja**: `src/commands/init.rs`, `src/commands/lock.rs`, `src/main.rs` (przed naprawą)
- **Szczegóły**: `register_driver_for_lock` zawsze znajdowała zarejestrowany
  `textconv` i zawsze zwracała `changed = true`, co `lock` wypisywał jako
  „repaired the filter registration in …". Fałszywy alarm w jedynym wyjściu, które
  użytkownik czyta w poszukiwaniu kłopotów, zanim klucz zniknie — a przy okazji
  `assert!(report.config_written)` w `lock.rs` przestawał cokolwiek dowodzić.
- **Naprawa**: `LockRegistration { repaired, diff_driver_removed }`; `lock::Report`
  dostał osobne pole, `main.rs` osobną linię komunikatu.
- **Test**: `a_healthy_lock_does_not_claim_to_have_repaired_anything`.
- **Decyzja**: NAPRAWIONE

### Obserwacje przebiegu 1

- Bare I/O bez nazwy pliku → dodane `named_io`, wzorem `lock::named_io`. NAPRAWIONE.
- Komentarz modułu o końcach linii argumentował odwrotnie, niż wychodziło z pomiaru
  → przepisany na zmierzoną prawdę. NAPRAWIONE.
- Gałąź deszyfrująca nietestowana przez gita → test
  `ciphertext_reaches_the_driver_when_no_filter_stands_in_front_of_it`. NAPRAWIONE.
- `outcome.warning` w `run_diff` dziś nieosiągalne → zostawione świadomie: to
  przekazanie dalej, a nie wymyślanie treści, i chroni przed cichym zgubieniem
  komunikatu, gdyby `smudge` kiedyś zaczął go zwracać dla treści zaszyfrowanej.
  POMINIĘTE.
- EPIPE daje kod 1 i komunikat → **odrzucone**. Zmierzone: git buforuje całe
  wyjście textconv, więc przez gita to nie zachodzi; ciche wyjście `0` przy
  urwanej rurze zamieniłoby obcięcie w sukces, a to jest kierunek, którego reguła
  fail-closed zabrania. ODRZUCONE.
- Cały plik do RAM na gałęzi przepuszczającej → **odrzucone jako niezmiana**: filtr
  i tak czyta całe pliki (API jednorazowe `aes-siv`), a strumieniowanie wymagałoby
  drugiego kształtu API dla tej samej decyzji. Otwarta decyzja 5 w `zalozenia.md`.
  ODRZUCONE.

## Przebieg 2 — luki w naprawach z przebiegu 1

### C1 — obrona przed `cachetextconv` nie działała wcale

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość
- **Lokalizacja**: `src/commands/init.rs` (po pierwszej naprawie)
- **Szczegóły**: `init` **usuwał** lokalny klucz `diff.git-xcrypt.cachetextconv`.
  Zmierzone: `[diff "git-xcrypt"] cachetextconv = true` w `~/.gitconfig` jest
  dziedziczone, a brak wpisu lokalnego niczego nie przebija — `git config --get`
  nadal zwracał `true`. Po `git log -p` odszyfrowane pliki lądowały w
  `refs/notes/textconv/git-xcrypt`, a po `git-xcrypt lock --yes` z usuniętym kluczem
  `git notes --ref=textconv/git-xcrypt` wciąż wydawał `api_key = SUPERSECRET`.
  Dokładnie ta awaria, przed którą komentarz w kodzie deklarował ochronę. Drugi
  otwór: cache utworzony wcześniej nie znikał w ogóle.
- **Naprawa**: `init` zapisuje **jawne `false`** (lokalne bije dziedziczone), a
  `textconv_cache_warning` wykrywa istniejący ref (luźny i w `packed-refs`) i
  raportuje go w `init` oraz w `lock` — z poleceniami `git update-ref -d` i
  `git gc --prune=now`. Kasowanie odrzucone świadomie: usunięcie refa zostawia
  obiekty w bazie, więc „posprzątane" byłoby nieprawdą.
- **Test**: `the_textconv_cache_is_switched_off_rather_than_merely_left_out`,
  `a_cache_that_already_exists_is_reported_rather_than_passed_over`,
  `init_registers_the_diff_driver_and_switches_the_cache_off` (przez `git config --get`,
  czyli przez pełną kaskadę, a nie przez plik lokalny).
- **Decyzja**: NAPRAWIONE

### C2 — zabezpieczenie klucza z przebiegu 1 obchodził katalog bieżący

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość
- **Lokalizacja**: `src/commands/diff.rs` (po pierwszej naprawie)
- **Szczegóły**: `refuse_private_path` pytało `Repo::discover_from_cwd()`, więc mówiło
  wyłącznie o repozytorium, w którym stoi proces. Zmierzone na tym samym pliku klucza:
  z wnętrza repozytorium — odmowa, kod 2; **spoza jakiegokolwiek repozytorium — 47
  bajtów klucza na `stdout`, kod 0**; z wnętrza *innego* repozytorium — to samo.
  Oba testy z przebiegu 1 przechodziły, bo harness zawsze ustawia `current_dir` na
  repozytorium. Strukturalnie poza zasięgiem tej kontroli leżały też kopia z
  `export-key` położona w drzewie roboczym i twarde dowiązanie.
- **Naprawa**: `keyfile::holds_a_key` — rozstrzygnięcie po **treści**, w `convert`,
  więc niezależne od katalogu, od nazwy i od liczby dowiązań; obejmuje obie postacie
  pliku klucza. Kontrola ścieżki została jako druga warstwa.
- **Test**: `a_key_file_is_never_printed_whatever_the_current_directory_is` (trzy
  cele, uruchamiane spoza repozytorium) plus test jednostkowy
  `a_key_file_is_refused_although_it_carries_no_data_magic`.
- **Decyzja**: NAPRAWIONE

### W1 — brak testu dla podłączonego worktree

- **Ważność**: ⚠️ OSTRZEŻENIE · **Wymiar**: Kryteria sukcesu
- **Lokalizacja**: `tests/decrypted_diff.rs`
- **Szczegóły**: `refuse_private_path` chodzi po `[git_dir(), common_dir()]`, a te
  różnią się wyłącznie w podłączonym worktree — jedynej konfiguracji bez pokrycia.
  Sprawdzone ręcznie, że działa; brakowało testu.
- **Naprawa**: `a_linked_worktree_diffs_on_the_plaintext_too` — różnica na treści
  jawnej plus odmowa dla ścieżki klucza, oba w podłączonym worktree.
- **Decyzja**: NAPRAWIONE

### Obserwacje przebiegu 2

- Brak regresji w rzeczach z przebiegu 1: `disable_help_flag` nie psuje pomocy nigdzie
  indziej, `git` zakłada pliki tymczasowe textconv w `$TMPDIR/git-blob-XXXXXX/`
  (nigdy w `.git`), warunek zapisu `changed || diff_driver_removed` jest poprawny,
  `canonicalize` na Windows porównuje obie strony tak samo, a wszystkie nowe testy
  padają po cofnięciu swojej funkcji.
- `named_io` gubi `ErrorKind` → **odrzucone**: `lock::named_io` robi dokładnie to
  samo, a spójność z sąsiadem jest tu warta więcej niż informacja, na której nic
  dziś nie rozgałęzia. ODRZUCONE.
- Odmowa jako `Error::Config` (kod 2) zamiast `Error::Usage` (kod 1) → **odrzucone**:
  `export_key::refuse_bad_destination` używa tego samego kodu dla analogicznej
  odmowy „to nie może tam trafić". ODRZUCONE.
- `LockRegistration` leżało między funkcjami zamiast przy `Report` → przeniesione
  wyżej, obok pozostałych typów wynikowych. NAPRAWIONE.
- Plik o nazwie dosłownie `--` nadal daje błąd użycia clapa (kod 2). Egzotyka;
  odnotowane, nienaprawiane. POMINIĘTE.
- Komunikat commita `930bbd3` wymienia test `difftool`, którego nie ma —
  `difftool` jest kryterium ręcznym (1.8) i został zweryfikowany pomiarem
  (`git difftool --no-prompt` na dwóch commitach pokazał `v1` i `v2` jawnie), ale
  komunikat brzmi, jakby był zautomatyzowany. Historia nie jest przepisywana.
  POMINIĘTE.
