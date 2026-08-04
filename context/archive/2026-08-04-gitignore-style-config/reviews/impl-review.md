<!-- IMPL-REVIEW-REPORT -->
# Przegląd implementacji: Synchronizacja `.gitattributes` z `.git-xcrypt`

- **Plan**: `context/archive/2026-08-04-gitignore-style-config/plan.md`
- **Zakres**: Fazy 1–2 z 2 (obie ukończone)
- **Data**: 2026-08-04
- **Werdykt**: ODRZUCONY po pierwszym przebiegu → ODRZUCONY po drugim → ZAAKCEPTOWANY
- **Ustalenia**: przebieg 1 — 1 krytyczne, 3 ostrzeżenia, 5 obserwacji;
  przebieg 2 — 2 krytyczne, 3 ostrzeżenia, 3 obserwacje
- **Przebiegi**: dwa. Drugi znalazł **dwie regresje wprowadzone naprawami z
  pierwszego** (G1, G2) oraz krytyczny błąd odziedziczony po S-01 (G5)

## Werdykty

| Wymiar | Przed naprawą | Po naprawie |
| --- | --- | --- |
| Zgodność z planem | PASS | PASS |
| Dyscyplina zakresu | PASS | PASS |
| Bezpieczeństwo i jakość | FAIL | PASS |
| Architektura | PASS | PASS |
| Spójność wzorców | PASS | PASS |
| Kryteria sukcesu | PASS | PASS |

Bramka jakości po naprawach: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
i `cargo test` (186 testów) przechodzą.

Sekcja, którą generuje dziś `sync` dla konfiguracji z negacją, `binary` i klasą
znaków — każdy werdykt sprawdzony przeciw `git check-attr` na git 2.55:

```
# >>> git-xcrypt >>>
* filter=git-xcrypt
**/secrets/** -text diff=git-xcrypt
*.env -text diff=git-xcrypt
**/*.env/** -text diff=git-xcrypt
secrets/README.md !text !diff
secrets/README.md/** !text !diff
secrets/key.p12 -text diff=git-xcrypt
secrets/key.p12/** -text diff=git-xcrypt
secrets/key.p12 -diff
secrets/key.p12/** -diff
# <<< git-xcrypt <<<
```

## Ustalenie krytyczne

### F1 — wzorzec katalogowy nie sięgał tak daleko jak filtr, więc `-text` gubiło się dokładnie tam, gdzie chroni

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/gitattributes.rs:108` (przed naprawą)
- **Szczegóły**: `.gitignore` **pływa** wzorcem, który nie ma własnego ukośnika:
  `secrets/` obejmuje także `app/secrets/x`, i tak samo robi `Config::decide`
  (przejście po katalogach nadrzędnych w `config.rs`). Wygenerowana linia
  `secrets/**` ukośnik ma, więc w `.gitattributes` jest **zakotwiczona w
  korzeniu** i nie sięga poza `secrets/…`. Ten sam rozjazd dotyczył wzorca bez
  końcowego ukośnika: `*.env` w `.gitignore` dopasowuje też katalog `a.env`, a
  filtr szyfruje jego zawartość — linia `*.env` w `.gitattributes` obejmuje sam
  plik.

  Dokumentacja modułu nazywała ten kierunek błędu nieszkodliwym („errs narrow").
  **To była błędna ocena.** Brak `-text` jest nieszkodliwy tylko dopóki ratuje
  nas autodetekcja gita po wiodącym NUL; jawny atrybut `text` — a `*.env text`
  we własnym `.gitattributes` użytkownika jest zupełnie zwyczajny — omija
  detekcję i git wykonuje konwersję CRLF **na wyjściu filtra**, czyli na
  ciphertexcie.

  Zmierzone na git 2.55, plik 2 MiB w `app/secrets/deep.env`, wzorzec
  `secrets/`, linia użytkownika `*.env text`:

  | rendering | blob | wynik |
  | --- | --- | --- |
  | `secrets/**` (przed) | 2 097 164 B zamiast 2 097 190 | 26 bajtów `CR` zjedzonych, `git add` kod **0**, commit przechodzi |
  | `**/secrets/**` (po) | 2 097 190 B | round-trip bajt w bajt |

  Przy starym renderingu `git checkout` kończył się
  `authentication failed; the file has been altered` i **plik znikał** —
  plaintext był zniszczony już przy `git add`, które zwróciło zero. Wprost
  przeciw guardrailowi PRD „filtr nigdy nie uszkadza pliku użytkownika".
- **Naprawa**: `translate` zwraca teraz **komplet** pisowni jednego wzorca:
  prefiks `**/` wszędzie tam, gdzie `.gitignore` pływa, plus osobna linia
  `.../**` na poddrzewo katalogu o tej nazwie. Rendering pokrywa dokładnie ten
  zbiór ścieżek, który szyfruje filtr.
- **Testy**: `tests/sync_command.rs::an_encrypted_file_survives_a_users_own_text_attribute`
  (odtwarza uszkodzenie end-to-end; przed naprawą czerwony),
  `a_directory_pattern_reaches_the_subtree_at_any_depth`,
  `src/gitattributes.rs::a_directory_pattern_covers_the_subtree_at_any_depth`,
  `a_file_pattern_also_covers_a_directory_of_that_name`.
- **Decyzja**: NAPRAWIONE

## Ostrzeżenia

### F2 — negacje zostawiały `-text` na plikach trzymanych jawnie

- **Ważność**: ⚠️ OSTRZEŻENIE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/gitattributes.rs:49` (przed naprawą)
- **Szczegóły**: plan i brief rozstrzygały „negacje pomijamy, bo
  `.gitattributes` nie ma dla nich sensownego odpowiednika". Odpowiednik jest:
  `!text !diff`. Bez niego `secrets/README.md` wyłączony negacją zostawał z
  `-text diff=git-xcrypt` odziedziczonym po szerszej linii — czyli git przestawał
  zarządzać końcami linii pliku, który leży w repozytorium jawnie, a po S-05
  `git diff` kierowałby na niego sterownik deszyfrujący. Zmierzone na git 2.55:
  `text: unset, diff: git-xcrypt` przed naprawą, `unspecified` po.
- **Naprawa**: nowy akcesor `Config::negated_patterns()` (tylko odczyt, parser
  nietknięty) i grupa linii `!text !diff` renderowana **na końcu** sekcji, bo git
  bierze ostatnie dopasowanie.
- **Testy**: `tests/sync_command.rs::a_negated_path_gets_gits_defaults_back`,
  `src/gitattributes.rs::a_negation_restores_gits_defaults_for_the_path`.
- **Decyzja**: NAPRAWIONE (świadome odejście od zapisu w planie — powód wyżej)

### F3 — `.gitattributes` i `.git/config` zapisywane nieatomowo

- **Ważność**: ⚠️ OSTRZEŻENIE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/gitattributes.rs:265`, `src/gitconfig.rs:55` (przed naprawą)
- **Szczegóły**: `fs::write` najpierw obcina plik, potem pisze. Awaria między
  jednym a drugim — brak miejsca, zanik zasilania — zostawia plik pusty lub
  skrócony. Pierwszą ofiarą jest linia `* filter=git-xcrypt`, czyli jedyna, na
  której wisi całe bezpieczeństwo; git widzi wtedy brak filtra i następny
  `git add` na sekrecie kończy się kodem `0` z plaintextem w bazie obiektów.
  Ten sam kształt miał zapis `.git/config`, gdzie ginie rejestracja sterownika.
  Dodatkowo obcięcie `.gitattributes` kasuje treść użytkownika spoza markerów,
  którą `upsert` obiecuje zachować.
- **Naprawa**: nowy moduł `src/atomic.rs` — zapis do pliku obok, `sync_all`,
  `rename` na miejsce. Używany przez `gitattributes::write_section` i
  `gitconfig::save_local`.
- **Decyzja**: NAPRAWIONE

### F4 — `binary` przegrywało, gdy szerszy wzorzec stał niżej

- **Ważność**: ⚠️ OSTRZEŻENIE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/gitattributes.rs:75` (przed naprawą)
- **Szczegóły**: linie szły w kolejności `.git-xcrypt`, a git rozstrzyga
  ostatnim dopasowaniem. Przy konfiguracji `secrets/key.p12 binary` **przed**
  `secrets/` wygenerowana linia `secrets/key.p12 -text -diff` stała nad
  `**/secrets/** … diff=git-xcrypt`, więc git raportował dla niej
  `diff: git-xcrypt` — dokładnie odwrotnie niż `Decision.suppress_diff`, dla
  którego ta linia powstała.
- **Naprawa**: trzy grupy zamiast jednej listy — linie nadające `diff`, potem
  linie je odbierające, potem negacje. Wewnątrz grupy nadal kolejność wejścia,
  więc wynik pozostaje czystą funkcją konfiguracji.
- **Test**: `a_line_that_takes_something_away_is_rendered_below_every_line_that_grants_it`.
- **Decyzja**: NAPRAWIONE

## Obserwacje

### F5 — markery wykrywane jako podciąg, nie jako cała linia

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/gitattributes.rs:233`
- **Szczegóły**: `contents.find(BEGIN)` trafiał również w komentarz użytkownika
  postaci `# >>> git-xcrypt >>> (legacy)`, więc następny zapis podmieniał
  wszystko od tej linii w dół — utrata treści, którą `upsert` obiecuje zachować.
- **Naprawa**: `marker_line()` dopasowuje marker jako **całą linię** (z tolerancją
  na CRLF). `has_section` celowo zostaje podciągiem: ta funkcja decyduje, czy
  `init` odmówi wygenerowania drugiego klucza, a tam bezpieczny kierunek to
  „zobaczyć ślad, którego nie ma", nie odwrotnie. Asymetria jest udokumentowana.
- **Test**: `a_marker_inside_a_user_comment_is_not_taken_for_the_section`.
- **Decyzja**: NAPRAWIONE

### F6 — wzorzec zaczynający się od `[attr]` stawał się definicją makra

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/gitattributes.rs:156`
- **Szczegóły**: `[attr]` to legalna klasa znaków w `.gitignore`, ale git czyta
  ten prefiks jako definicję makra, **zanim** dojdzie do cudzysłowów. Linia
  `[attr]x -text diff=git-xcrypt` definiowała makro `x` i nie dopasowywała
  niczego. Zmierzone na git 2.55.
- **Naprawa**: taki wzorzec jest cytowany C-stylem, co kieruje git do gałęzi
  wzorca. Pisownia poddrzewa zaczyna się od `**/`, więc jej to nie dotyczy.
- **Decyzja**: NAPRAWIONE

### F7 — nieczytelny `.gitattributes` dawał komunikat bez nazwy pliku

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/gitattributes.rs:281`
- **Szczegóły**: `read_to_string` zgłasza „stream did not contain valid UTF-8"
  jako błąd I/O — użytkownik nie dowiadywał się, o który plik chodzi ani co
  zrobić.
- **Naprawa**: `InvalidData` mapowane na `Error::Config` z nazwą pliku (kod `2`).
- **Decyzja**: NAPRAWIONE

### F8 — `sync --check` dzieli kod `1` z błędem narzędzia

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/main.rs:135`
- **Szczegóły**: nieaktualna sekcja i `Error::Io` kończą się tym samym kodem `1`,
  więc bramka CI nie odróżni ich bez czytania komunikatu. Zamrożona tabela nie ma
  wolnego kodu, a `5` znaczy ekspozycję, którą kosmetyczna sekcja nie jest.
- **Decyzja**: ZAAKCEPTOWANE — kolizja udokumentowana przy `run_sync`; zmiana
  wymagałaby ruszenia zamrożonej tabeli.

### F9 — `sync` działa w repozytorium bez klucza i bez rejestracji filtra

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/commands/sync.rs:45`
- **Szczegóły**: komenda zapisze `* filter=git-xcrypt` również tam, gdzie nic
  innego nie jest skonfigurowane. Niegroźne (niezdefiniowany filtr to dla gita
  brak filtra), a kompletność konfiguracji jest zadaniem `status` z S-06.
- **Decyzja**: ZAAKCEPTOWANE

## Drugi przebieg — regresje po naprawach i to, co umknęło

Metoda: eksperyment różnicowy przeciw prawdziwemu gitowi 2.55 — ~60 sond
ścieżkowych na 26 konfiguracjach, porównanie „czy blob zaczyna się od magic"
z `git check-attr text diff`.

### G1 — cytowanie `[attr]` nie działało, a fix z F6 tak twierdził

- **Ważność**: ❌ KRYTYCZNE (regresja naprawy F6) · **Lokalizacja**: `src/gitattributes.rs:231` (przed naprawą)
- **Szczegóły**: F6 zakładało, że git sprawdza prefiks makra **po** zdjęciu
  cudzysłowów. Jest odwrotnie. Zmierzone: `"[attr]x" -text diff=zz`,
  `[attr]x -text diff=zz` i `\[attr\]x -text diff=zz` dają dla ścieżki `ax`
  identyczne `text: unspecified` — wszystkie trzy są dla gita definicją makra.
  Plik w korzeniu nie dostawał więc żadnej linii, a stąd wracał tryb awarii F1:
  przy `ax text` w pliku użytkownika i pliku 2 MiB blob wyszedł o 34 bajty
  krótszy, `git add` kod `0`, `git checkout` → `authentication failed`, plik
  zniknął.
- **Naprawa**: nie cytowanie, tylko pisownia — `**/[attr]x` dla wzorca
  pływającego i `/[attr]x/y` dla zakotwiczonego. Oba znaczą w korzeniu
  dokładnie to samo co wersja bez prefiksu i nie trafiają w gałąź makra.
- **Testy**: `a_pattern_opening_with_attr_is_kept_out_of_gits_macro_branch`,
  `tests/sync_command.rs::a_character_class_pattern_stays_a_pattern`.
- **Decyzja**: NAPRAWIONE. Lekcja: naprawa oparta na przeczytanym kodzie C
  gita, a nie na pomiarze, myliła się co do kolejności dwóch gałęzi parsera.

### G2 — negacje na końcu sekcji odwracały selekcję

- **Ważność**: ⚠️ OSTRZEŻENIE (regresja naprawy F2) · **Lokalizacja**: `src/gitattributes.rs:98` (przed naprawą)
- **Szczegóły**: F2 renderowało wszystkie negacje w grupie na końcu, bo tak
  wymaga **oś atrybutów**. Ale selekcja rozstrzyga się **ostatnim dopasowaniem**
  — i w gicie, i w `Config::decide` (pilnuje tego test S-01
  `the_last_selecting_line_wins`). Konfiguracja `!secrets/README.md` **nad**
  `secrets/` szyfruje ten plik, a wygenerowana sekcja kończyła się na
  `!text !diff`. Zmierzone: blob zaczyna się od magic, a `git check-attr` mówi
  `text: unspecified` — czyli zaszyfrowany plik bez `-text`, dokładnie to, przed
  czym broni F1. Przed F2 ta ścieżka była poprawna.
- **Naprawa**: linie selekcji i negacji idą teraz **w kolejności pliku**, tak jak
  rozstrzyga git. Na oś atrybutów zostaje osobna, końcowa grupa `<wzorzec> -diff`
  dla wzorców z `binary` — nazywa tylko `diff`, więc ustalone wyżej `-text`
  przeżywa. `Config::selecting_patterns`/`negated_patterns` zastąpione jednym
  widokiem `Config::patterns()` zachowującym pozycję.
- **Testy**: `a_negation_a_later_pattern_overrules_does_not_reach_the_bottom_of_the_section`,
  `tests/sync_command.rs::a_negation_a_later_pattern_overrules_keeps_the_attributes_of_an_encrypted_file`.
- **Decyzja**: NAPRAWIONE

### G3 — pliki bootstrapowe dostawały `-text` mimo że leżą jawnie

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/gitattributes.rs:59`
- **Szczegóły**: `render_lines` renderowało z surowych wzorców i nic nie
  wiedziało o `config::is_never_encrypted`. Zmierzone przy `core.autocrlf=true`
  i wzorcu `secrets/`: `secrets/.gitattributes` leży w bazie jawnie (poprawnie),
  ale `text: unset` — git przestał normalizować jego końce linii. Naprawa F1
  pogłębiła zasięg: `**/secrets/**` trafia teraz w każdy poziom, wcześniej tylko
  w korzeń. Zagnieżdżony `.gitattributes` to nie egzotyka — ma go każde repo
  ustawiające atrybuty per katalog.
- **Naprawa**: `Config::decide_ignoring_exclusions` plus końcowe linie
  `**/.gitattributes !text !diff`, `/.git-xcrypt !text !diff`,
  `/.git-xcrypt-keys/** !text !diff`, emitowane **tylko** gdy któryś wzorzec
  faktycznie w nie trafia — zwykła konfiguracja ich nie nosi, więc nie nadpisują
  atrybutów, które użytkownik ustawił sobie sam.
- **Testy**: `a_broad_pattern_gives_the_bootstrap_files_their_defaults_back`,
  `tests/sync_command.rs::a_broad_pattern_leaves_the_bootstrap_files_to_git`.
- **Decyzja**: NAPRAWIONE

### G4 — zapis atomowy gubił uprawnienia pliku

- **Ważność**: ⚠️ OSTRZEŻENIE (regresja naprawy F3) · **Lokalizacja**: `src/atomic.rs:37`
- **Szczegóły**: `fs::write` otwierało **istniejący** plik, więc tryb przeżywał.
  `File::create` tworzy nowy z `0666 & ~umask`, a `rename` podmienia razem z
  trybem. Zmierzone na macOS przy umask 022: `chmod 600 .git/config` + `init` →
  `-rw-r--r--`. `.git/config` rutynowo trzyma `[credential]` i URL-e zdalne z
  tokenami, więc rozszerzenie go do world-readable to realna, choć wąska,
  ekspozycja. Plik klucza **nie** jest dotknięty — `keyfile::write_owner_only`
  ma własną ścieżkę z jawnym `0600`.
- **Naprawa**: uprawnienia istniejącego celu są kopiowane na plik tymczasowy
  przed `rename`.
- **Test**: `src/atomic.rs::a_narrowed_target_keeps_its_permissions`.
- **Decyzja**: NAPRAWIONE

### G5 — `init` w podłączonym worktree cicho zapisywał plaintext

- **Ważność**: ❌ KRYTYCZNE (odziedziczone po S-01, **poza zakresem planu**) · **Lokalizacja**: `src/repo.rs:83`
- **Szczegóły**: git dir podłączonego worktree to `.git/worktrees/<nazwa>`, a
  `Repo::config_path()` sklejało `config` właśnie z nim. Git ignoruje ten plik,
  dopóki nie ustawiono `extensions.worktreeConfig`. Zmierzone na git 2.55:

  ```
  git worktree add ../wt && cd ../wt && git-xcrypt init
  → „registered the filter in .../worktrees/wt/config"
  git config --get filter.git-xcrypt.process   → (nic)
  git add secrets/p && git commit
  git cat-file blob HEAD:secrets/p → TOPSECRET
  ```

  `init` raportował sukces, klucz powstawał, `.gitattributes` dostawał linię
  catch-all — i każdy sekret commitowany z tego worktree lądował jawnie. Klucz
  też był per worktree, więc nie odszyfrowałby tego, co zacommitowały pozostałe.
- **Naprawa**: `Repo` rozwiązuje teraz **wspólny katalog** (plik `commondir`) i
  z niego bierze ścieżkę konfiguracji oraz klucza; `filter` czyta konfigurację
  gita stamtąd samo.
- **Test**: `tests/filter_edge_cases.rs::init_in_a_linked_worktree_registers_where_git_actually_reads`
  (+ pomocnik `TestRepo::add_worktree`).
- **Decyzja**: NAPRAWIONE mimo że leży poza planem S-02 — reguła „nigdy nie
  przepuszczaj treści po cichu" waży więcej niż dyscyplina zakresu, a naprawa
  jest lokalna. **Do świadomej akceptacji przez człowieka.**

### Obserwacje z drugiego przebiegu

- **Brak `fsync` katalogu po `rename`** — obietnica z `atomic.rs` trzymała tylko
  wtedy, gdy cel już istniał; przy tworzeniu `.gitattributes` awaria zaraz po
  `init` zostawiała repozytorium z kluczem, rejestracją i **bez** linii
  catch-all. Dodany `sync_all` na katalogu (best effort). NAPRAWIONE.
- **Plik tymczasowy zostaje po `SIGKILL`** i jest niesegregowany w drzewie
  roboczym, więc `git add -A` mógłby go zacommitować. Treść to tekst atrybutów,
  nigdy sekret. Udokumentowane w `atomic.rs`; ZAAKCEPTOWANE.
- **Dowiązanie symboliczne jako `.gitattributes`** jest zastępowane zwykłym
  plikiem (`fs::write` szło za linkiem). Udokumentowane; ZAAKCEPTOWANE.
- **`core.ignorecase` vs `Case::Sensitive` w filtrze** — na macOS i Windows git
  dopasowuje wzorce bez rozróżniania wielkości liter, a filtr rozróżnia. Zmierzone:
  przy wzorcu `secrets/` ścieżka `Secrets/db.env` **nie jest szyfrowana**, choć
  `git check-ignore` ją dopasowuje. To semantyka selekcji z S-01 i realny problem,
  ale zmiana na `Case::Fold` czytałaby konfigurację na ścieżce clean, czyli
  uzależniłaby zbiór szyfrowanych plików od maszyny. **ZAAKCEPTOWANE jako
  znalezisko dla S-06 / dokumentacji — wymaga decyzji człowieka.**

### Potwierdzone jako poprawne w drugim przebiegu

- Arytmetyka `upsert` po przejściu na markery liniowe — prześledzona dla braku
  końcowego znaku nowej linii, CRLF, END jako ostatniej linii, END przed BEGIN i
  wielu BEGIN. Wszystkie offsety pochodzą z granic linii, więc żadne cięcie
  napisu nie może trafić w środek znaku wielobajtowego.
- Idempotencja przy CRLF — sprawdzona na prawdziwym repozytorium.
- Cytowanie w `spell` — round-trip przez `unquote_c_style` dla spacji, tabulacji,
  `\r`, odwrotnego ukośnika i bajtów spoza ASCII.
- Reguły twarde: brak nowych zapisów na `stdout`, zero `unsafe`, brak
  `unwrap`/`expect` na danych wejściowych poza testami; `required = true` nadal
  ląduje, odmowa `init` w klonie bez klucza nadal działa.

## Rozjazdy planu wobec stanu kodu

Odnotowane, nie naprawiane w kodzie:

- Plan wskazuje plik `src/attributes.rs`; sekcja zarządzana i `upsert` mieszkają
  od S-01 w `src/gitattributes.rs` i tam trafiła reszta. Drugi moduł rozbiłby
  własność tego samego pliku.
- Plan mówi „wzorce z wiodącym `/` tracą go". Zmierzone: wiodący `/` kotwiczy
  również w `.gitattributes`, a jego usunięcie rozlewa `-text` na pliki
  nieszyfrowane. Wiodący ukośnik zostaje.
- Plan mówi „`binary` daje linię bez `diff`". Samo pominięcie nie wystarcza —
  patrz F4; renderujemy jawne `-diff`, zgodnie z makrem `binary` z gita.
- Plan i brief mówią „negacje pomijamy" — patrz F2.
- **Zmiana kontraktu `init` (S-01)**: `init` renderuje teraz sekcję z
  `.git-xcrypt`, więc nieczytelny plik konfiguracyjny zatrzymuje komendę kodem
  `2` **po** zapisaniu rejestracji sterownika. Naprawa i tak ląduje, a komunikat
  wskazuje wadliwą linię; ten sam plik zatrzymuje każde `git add`.
