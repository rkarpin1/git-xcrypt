<!-- IMPL-REVIEW-REPORT -->
# Przegląd implementacji: Zamknięcie repozytorium

- **Plan**: `context/changes/lock-repository/plan.md`
- **Zakres**: Faza 1 z 1 (ukończona)
- **Data**: 2026-08-04
- **Werdykt**: ODRZUCONY po pierwszym przebiegu → ODRZUCONY po drugim → ZAAKCEPTOWANY
- **Ustalenia**: przebieg 1 — 2 krytyczne, 5 ostrzeżeń, 3 obserwacje;
  przebieg 2 — 2 krytyczne, 5 ostrzeżeń, 5 obserwacji
- **Przebiegi**: dwa. Drugi znalazł **cztery regresje wprowadzone naprawami z pierwszego**
  (C1, C2, W1, W2) — w tym dwie prowadzące dokładnie do tego stanu, którego cała komenda
  ma nie dopuścić: klucz usunięty, żywy katalog roboczy jawny.

## Werdykty

| Wymiar | Przed naprawą | Po naprawie |
| --- | --- | --- |
| Zgodność z planem | WARNING | PASS |
| Dyscyplina zakresu | WARNING | PASS |
| Bezpieczeństwo i jakość | FAIL | PASS |
| Architektura | PASS | PASS |
| Spójność wzorców | PASS | PASS |
| Kryteria sukcesu | PASS | PASS |

Bramka jakości po naprawach: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
i `cargo test` (221 testów jednostkowych + 73 integracyjnych) przechodzą.

## Przebieg 1

### F1 — okno między dowodem a zapisem obejmowało cały czas trwania pytania

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: sprawdzenie „treść jest już blobem" biegło przed pytaniem, a `encrypt_in_place`
  świadomie czytał plik **ponownie** przed zapisem. Między jednym a drugim leżało oczekiwanie
  na odpowiedź człowieka — czas nieograniczony, dokładnie wtedy, gdy odpala się autozapis edytora.
  Zmierzone: plik nadpisany 2 s po wyświetleniu ostrzeżenia został zaszyfrowany, klucz usunięty,
  a treści nie było w żadnym obiekcie gita. To jest ta utrata, przed którą sprawdzenie istnieje,
  i której `--yes` jawnie nie wolno obchodzić.
- **Naprawa**: `survey()` zapamiętuje oczekiwany `blob_id` każdego pliku; `encrypt_in_place`
  przelicza go i porównuje **przed** zapisem, przerywając przy rozjeździe. Klucz zostaje.
- **Test**: `an_edit_made_while_the_prompt_waits_stops_the_run_instead_of_being_locked_in`.
- **Decyzja**: NAPRAWIONE

### F2 — `lock` w jednym worktree kasował klucz wspólny dla wszystkich

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: klucz leży we wspólnym katalogu (poprawnie, `repo.key_path()` idzie przez
  `common_dir`), a przejście po drzewie widzi tylko jeden checkout. Zmierzone: `lock --yes`
  w głównym worktree zaszyfrował jego pliki i usunął klucz, podłączony worktree został z
  **jawnym** `secrets/db.env`, a `lock` tam zwrócił kod `3`. Dosłownie „stan, którego ta komenda
  nie może wyprodukować" z nagłówka modułu — osiągnięty na ścieżce sukcesu, nie przez przerwanie.
- **Naprawa**: `refuse_other_worktrees` — odmowa, gdy istnieje inny checkout, z listą i drogą wyjścia.
- **Test**: `tests/lock_command.rs::another_checkout_of_the_same_repository_stops_lock`.
- **Decyzja**: NAPRAWIONE

### F3 — zamiatanie plików tymczasowych kasowało pliki użytkownika

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/lock.rs`, `src/atomic.rs` (przed naprawą)
- **Szczegóły**: sprzątanie sierot po zabitym `unlock` szło po samej nazwie, więc kasowało
  **każdy** plik o tym kształcie — również śledzony i również poza zakresem wzorców. Zmierzone:
  zacommitowany `build.git-xcrypt-deadbeefcafef00d.tmp` i nieśledzony
  `docs/notes.git-xcrypt-0011223344556677.tmp` zniknęły, drugi bezpowrotnie, a `git status`
  został brudny — wbrew własnemu kryterium 1.2. Lista kasowania była też ujawniana **po** fakcie.
- **Naprawa**: `atomic::strip_temporary_suffix` zwraca cel zamiast tak/nie, więc zamiatanie
  wymaga trzech warunków: kształt nazwy (16 małych cyfr szesnastkowych), cel objęty deklaracją,
  plik nieśledzony. Lista trafia do `Warning`, czyli **przed** pytanie.
- **Testy**: `a_tracked_file_shaped_like_our_residue_is_not_deleted`,
  `the_sweep_is_disclosed_before_the_question_not_after_it`,
  `a_temporary_name_is_recognised_by_its_target_and_nothing_else_is`.
- **Decyzja**: NAPRAWIONE

### F4 — `lock` nie sprawdzał zabezpieczenia, które po sobie zostawia

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: `unlock` i `import-key` naprawiają rejestrację sterownika i linię catch-all,
  bo git czyta brakujący atrybut tak samo jak niezdefiniowany sterownik — jako brak filtra.
  `lock` nie robił ani jednego, a jest **ostatnią** komendą przed zniknięciem klucza. Zmierzone
  w dwóch repozytoriach: po `lock` z usuniętą linią catch-all (i osobno z usuniętą sekcją
  `filter.git-xcrypt`) `git add secrets/fresh.env` kończył się kodem `0` i plaintext lądował
  w bazie obiektów.
- **Naprawa**: naprawa obu połówek, ale wyłącznie tego, czego **brakuje** — patrz W1 i W2
  z drugiego przebiegu, które ograniczyły pierwotną, zbyt szeroką wersję tej naprawy.
- **Test**: `lock_repairs_the_registration_it_is_about_to_depend_on`.
- **Decyzja**: NAPRAWIONE

### F5 — „0 plików zaszyfrowanych" opisywało dwa różne repozytoria

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/main.rs`, `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: przy jednoliterowej literówce w `.git-xcrypt` (`sekrety/` zamiast `secrets/`)
  komenda kończyła się „locked; 0 file(s) are now encrypted", kasowała klucz, a `secrets/db.env`
  zostawał jawny. Nie do odróżnienia od legalnego przypadku klonu, który nigdy nie był odblokowany.
- **Naprawa**: `Report.declared` obok `encrypted`; trzy różne linie zamykające, plus ostrzeżenie
  **w treści pytania**, gdy deklaracja nie trafia w nic.
- **Testy**: `a_declaration_that_matches_nothing_is_said_out_loud`,
  `a_clone_that_never_unlocked_can_still_be_locked_into_shape`.
- **Decyzja**: NAPRAWIONE

### F6 — odmowa podawała radę, która nie działa

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: wszystkie przypadki dostawały „Commit or stash it first". Dla pliku
  zacommitowanego **jawnie** zanim wzorzec go objął (dokładnie scenariusz S-06) treść *jest*
  zapisana, plik jest niezmieniony, więc `git commit` nie robi nic — działa `git add`. Dla pliku
  ignorowanego przez `.gitignore` `git stash` go nie dotknie, a `git add` wymaga `-f`. Obie
  sytuacje kończyły się kodem `2` bez wyjścia.
- **Naprawa**: trzy stany (`Untracked`, `InTheClear`, `Modified`), grupowane, każdy z własnym
  środkiem zaradczym; przy ekspozycji komunikat mówi też o rotacji sekretu.
- **Test**: `a_secret_stored_in_the_clear_is_named_as_an_exposure_not_as_an_edit`.
- **Decyzja**: NAPRAWIONE

### F7 — `staged_ids` odpowiadało tylko na pierwsze wystąpienie ścieżki

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/gitindex.rs` (przed naprawą)
- **Szczegóły**: `paths.iter().position(...)` wypełniało jedną pozycję. `lock` pyta o selekcję
  i o kandydatów do zamiatania w jednym zapytaniu, a plik może być w obu — druga pozycja czytała
  się wtedy jako „nieśledzony", czyli jako „skasuj". Znalezione przez własny test F3, nie przez
  lekturę.
- **Naprawa**: wypełniane są wszystkie pasujące pozycje.
- **Test**: `the_same_path_asked_about_twice_is_answered_twice`.
- **Decyzja**: NAPRAWIONE

### Obserwacje z przebiegu 1, naprawione

- Podzielony indeks kończył `lock` bez wskazania wyjścia — komunikat podaje
  `git update-index --no-split-index`.
- Awaria w połowie przejścia szyfrującego gubiła cały `Report` — `interrupted()` dopisuje, ile
  plików już zamknięto, ile sierot skasowano i że klucz **został**.
- Prompt czyta `stdin`, nie `/dev/tty`, więc `lock 2>/dev/null` czeka na niewidoczne pytanie,
  a `lock < plik` odpowiada za użytkownika. Nie ma przenośnego odpowiednika `/dev/tty`;
  ZAAKCEPTOWANE i udokumentowane przy `Ask`.

## Przebieg 2 — regresje po naprawach i to, co umknęło

Metoda: pomiary na prawdziwym git 2.55 (worktree zwykłe, przeniesione, `--separate-git-dir`,
podzielony indeks, konflikty scalania, `index.skipHash`, repozytoria SHA-256, nazwy 4094–5000 B,
NFD/NFC, `core.ignorecase`) plus ~28 000 iteracji fuzzingu `src/gitindex.rs` z każdorazowym
przeliczeniem sumy kontrolnej, aby bramka sumy nie maskowała błędów parsera.

### C1 — odmowa dla worktree decydowała ze wskaźnika zwrotnego, rozwiązywanego względem `cwd`

- **Ważność**: ❌ KRYTYCZNE (regresja naprawy F2) · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: `worktrees/<nazwa>/gitdir` bywa **względny**, a `Path::exists()` mierzy go od
  katalogu procesu. Zmierzone: `lock --yes` z korzenia repozytorium → kod `2`, klucz zostaje;
  ta sama komenda z podkatalogu `secrets/` → kod `0`, klucz usunięty, podłączony worktree jawny.
  Drugi wariant tej samej przyczyny: checkout przeniesiony przez `mv` (nie `git worktree move`)
  żyje w pełni, a jego wskaźnik nie prowadzi już nigdzie — też był brany za zapis nieaktualny.
- **Naprawa**: dowodem jest **katalog rejestracji**, nie wskaźnik. Wskaźnik służy wyłącznie do
  nazwania checkoutu w komunikacie i jest rozwiązywany względem rejestracji. Naprawdę nieaktualny
  wpis kosztuje jedno `git worktree prune`, wymienione w komunikacie.
- **Test**: `a_checkout_whose_back_pointer_is_broken_still_stops_lock`.
- **Decyzja**: NAPRAWIONE

### C2 — główny checkout nie był wykrywany, gdy wspólny katalog nie nazywa się `.git`

- **Ważność**: ❌ KRYTYCZNE (regresja naprawy F2) · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: warunek `common_dir.file_name() == ".git"` pomijał cały przypadek
  `git init --separate-git-dir`. Zmierzone: `lock --yes` z **podłączonego** worktree kończył się
  zerem i usuwał klucz, a główny checkout zostawał nie tylko jawny, ale niezdolny do wykonania
  `git status` — przy `required = true` i braku klucza każde wywołanie filtra zawodzi.
  Kierunek główny→podłączony był łapany, więc odmowa była asymetryczna.
- **Naprawa**: `main_checkout()` czyta `core.worktree`, honoruje `core.bare`, a gdy żadna droga
  nie odpowiada — **odmawia** z adnotacją, że lokalizacji nie ustalono. Zgadywanie „nie ma
  checkoutu" to zgadywanie, które kasuje klucz.
- **Decyzja**: NAPRAWIONE

### W1 — naprawa F4 zostawiała brudny `git status` po udanym `lock`

- **Ważność**: ⚠️ OSTRZEŻENIE (regresja naprawy F4) · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: `.git-xcrypt` jest jedynym źródłem prawdy, jego linie w `.gitattributes` są
  kosmetyczne, a rozjazd jest **udokumentowanym stanem normalnym** (`sync` go usuwa). `lock`
  przepisywał sekcję po cichu. Zmierzone: `git status` czysty przed, `" M .gitattributes"` po —
  bez ujawnienia w ostrzeżeniu, po potwierdzeniu i po usunięciu klucza. Łamało to kryterium 1.2.
- **Naprawa**: zapisywana jest wyłącznie **brakująca** linia catch-all (`gitattributes::CATCH_ALL`
  upublicznione); sekcja jedynie nieaktualna zostaje nietknięta.
- **Test**: `a_cosmetic_drift_in_gitattributes_does_not_dirty_the_tree`.
- **Decyzja**: NAPRAWIONE

### W2 — naprawa F4 przestawiała sterownik na binarkę, która akurat go uruchomiła

- **Ważność**: ⚠️ OSTRZEŻENIE (regresja naprawy F4) · **Lokalizacja**: `src/commands/init.rs` (przed naprawą)
- **Szczegóły**: `register_driver` zapisuje `current_exe()`. `init` i `unlock` też, ale to komendy
  **przed** utratą klucza. Po `lock` nie ma już czym naprawiać: `unlock` potrzebuje klucza, a `init`
  odmawia w repozytorium ze śladami i bez klucza. Zmierzone: `lock` uruchomiony z kopii binarki
  przestawił rejestrację na jej ścieżkę; po usunięciu tej ścieżki `git add -A` kończył się
  `fatal: … clean filter 'git-xcrypt' failed`, a `git-xcrypt init` odmawiał. Wystarczy
  `cargo run`, binarka z `~/Downloads` albo montowanie w kontenerze.
- **Naprawa**: `register_driver_if_absent` — istniejąca wartość `process` nie jest ruszana nigdy;
  zapisywana jest tylko nieobecna, a `required` wymuszane zawsze (może wyłącznie odmówić więcej).
- **Testy**: `a_working_registration_is_never_repointed_at_this_binary`,
  `a_missing_registration_is_still_put_back`.
- **Decyzja**: NAPRAWIONE

### W3 — plik, który **pojawił się** w trakcie pytania, był omijany

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: naprawa F1 łapie **edycję** pliku, który był w selekcji. Plik utworzony w tym
  samym oknie nie jest w selekcji w ogóle, więc żadne sprawdzenie per plik go nie zobaczy.
  Zmierzone: `secrets/late.env` utworzony 1,5 s po wyświetleniu pytania przeżył udany `lock`
  jawnie, bez ostrzeżenia, przy usuniętym kluczu.
- **Naprawa**: `refuse_if_the_tree_moved` — ponowne przejście po drzewie po potwierdzeniu,
  odmowa przy jakiejkolwiek zmianie zbioru. Wykonywane **przed** pierwszym zapisem.
- **Test**: `a_declared_file_that_appears_while_the_prompt_waits_stops_the_run`.
- **Decyzja**: NAPRAWIONE

### W4 — drugi `lock` po przerwanym zostawiał pliki trwale „zmodyfikowane"

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: do `forget_stat` szły wyłącznie pliki zapisane **w tym** uruchomieniu, a drugi
  przebieg pomija pliki już zaszyfrowane. Zmierzone: `lock` przerwany na drugim pliku, potem
  `lock` udany → `" M secrets/aa/1.env"` na stałe. Obietnica modułu („running lock again finishes
  the job") nie obowiązywała.
- **Naprawa**: do `forget_stat` idą **wszystkie** wybrane ścieżki. Dodatkowo, skoro `survey`
  dowiódł, że każda z nich jest śledzona, `Cleared(n) < n` znaczy rozjazd pisowni nazwy i jest
  raportowane zamiast milczeć.
- **Test**: `a_second_lock_after_an_interrupted_one_leaves_a_clean_tree`.
- **Decyzja**: NAPRAWIONE

### W5 — `named()` gubił ścieżkę dla `Error::Io` i `Error::KeyMismatch`

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/lock.rs` (przed naprawą)
- **Szczegóły**: dwa komunikaty, które najbardziej potrzebowały nazwy pliku, nie miały jej.
  Zmierzone: `i/o failure: Permission denied (os error 13)` w połowie przepisywania drzewa
  roboczego, oraz `this file was encrypted with key e369bfaf…` — „this file" nie nazywa pliku.
- **Naprawa**: `named` obsługuje `Io` (zachowując kod `1`) i `KeyMismatch` (jako `Format`, czyli
  ten sam kod `4`, ale z nazwą pliku). `NoKey` przechodzi nietknięte, bo dotyczy repozytorium.
- **Decyzja**: NAPRAWIONE

### Obserwacje z przebiegu 2

- **Rozjazd pisowni nazw** (`core.ignorecase` na macOS i Windows, NFD wobec NFC przy
  `core.precomposeunicode`) sprawia, że ten sam plik ma dwie nazwy: git trzyma tę, pod którą
  został dodany, katalog tę z dysku. Zmierzone na git 2.55/APFS. Skutki dla `lock` są po
  bezpiecznej stronie (odmowa), a rozjazd jest teraz **zgłaszany** zamiast milczeć, ale realna
  naprawa to rozstrzygnięcie, co znaczy *wzorzec* — czyli pozycja odłożona już przy S-02.
  **Wymaga decyzji człowieka.**
- `str::trim` uznaje U+00A0 za biały znak, więc `\u{a0}yes` było zgodą. Porównanie obcina teraz
  wyłącznie białe znaki ASCII.
- `git add -N` zapisuje pusty blob, więc taka ścieżka trafiała do grupy „zmienione", a `git commit`
  odmawia jej wprost. Komunikat prowadzi teraz `git add`.
- `scan` nie filtruje po `stage`, `staged_ids` filtruje — asymetria zweryfikowana jako nieszkodliwa
  (wpis konfliktowy i tak ma wyzerowany blok `stat`) i opisana w kodzie.
- Sierota po zabitym `unlock`, której cel przestał być objęty deklaracją, nie jest zamiatana —
  świadome zawężenie z F3; jest za to nazywana w ostrzeżeniu. ZAAKCEPTOWANE.

### Potwierdzone jako poprawne w przebiegu 2

- **`src/gitindex.rs` przeciw prawdziwemu gitowi**: `staged_ids` zgodne z `git rev-parse :<ścieżka>`
  i `git ls-files --stage` w 12 konfiguracjach (wersje indeksu 2/3/4 × SHA-1/SHA-256 ×
  zwykły/`index.skipHash`), łącznie z gitlinkiem, spacjami, tabulatorami, nazwami spoza ASCII,
  `skip-worktree` (CE_EXTENDED), `assume-unchanged` (CE_VALID) i `git add -N`. Nazwy 4094/4095/
  4096/4097/5000 B (gałąź nasycenia `0xfff`) poprawne w każdej wersji, również w połączeniu
  z rozszerzonymi flagami. Kompresja prefiksowa wersji 4 wraz z `strip == previous.len()`.
  Konflikty czytane jako `None`. Rozszerzenia TREE/UNTR/REUC/EOIE/IEOT oraz indeks bez rozszerzeń
  przechodzone co do ostatniego bajtu. Podzielony indeks odmawiany.
- **Fuzzing**, ~28 000 iteracji z resetowaną sumą kontrolną: **0 panik**, 0 błędnych odpowiedzi
  wobec prawdziwego gita (3600 iteracji porównanych), 0 przypadków, w których `forget_stat`
  zamienił indeks akceptowany przez gita w odrzucany, 0 zmian nazw i identyfikatorów obiektów.
  Mutacje pola `count` i ogona łapane w 1200/1200 przypadkach przez wymóg „przejście po
  rozszerzeniach musi trafić w ostatni bajt".
- **`drop_swept`** — wyrównanie listy kandydatów i listy identyfikatorów sprawdzone przy usunięciu
  ze środka, wielu usunięciach, braku usunięć i przy śledzonej sierocie zostawionej w selekcji.
  Round-trip `lock → unlock` zwrócił każdemu plikowi jego treść, więc żaden plik nie był porównany
  z identyfikatorem sąsiada.
- **`git status` czysty po `lock` i po round-tripie** w: CRLF przy `core.autocrlf=true`, bit
  wykonywalności, nazwy spoza ASCII, ze spacjami i ze znakami nowej linii, `--object-format=sha256`,
  `index.skipHash`, puste repozytorium, repozytorium bez commitów, niezacommitowany `.gitattributes`.
- **`stdout` pusty na wszystkich dziewięciu ścieżkach** komendy (sukces, brak klucza, odmowa przy
  niezapisanej treści, odmowa przy worktree, brak deklaracji, przerwanie przez `no`, przerwanie
  przez EOF, błąd formatu, brak repozytorium) — po 0 bajtów.
- **Kody wyjścia** zgodne z zamrożoną tabelą: `0` / `1` (przerwanie, niesklasyfikowane I/O) /
  `2` (konflikt stanu, podzielony indeks, inny checkout) / `3` (brak klucza) / `4` (format).
- **Higiena**: zero `unsafe`; brak `unwrap`/`expect` na danych wejściowych poza testami; żaden
  materiał klucza nie pojawia się w wyjściu (sprawdzone wobec base64 z eksportu i wobec każdego
  8-bajtowego okna surowego klucza).

## Rozjazdy planu wobec stanu kodu

Odnotowane, nie naprawiane w planie:

- **Brudny katalog wykrywany wobec *indeksu*, nie wobec `HEAD`.** Plan mówi „porównujemy
  zaszyfrowaną postać z blobem z `HEAD`". Odczyt `HEAD` wymaga bazy obiektów, czyli crate'a
  `gix-odb` (rozpakowywanie loose i paczek) — nowej zależności, której plan nie przewidział.
  Indeks daje odpowiedź **dokładniejszą wobec faktycznego ryzyka**: pyta „czy ta treść jest już
  blobem w tym repozytorium", a to jest przesłanka, na której zabezpieczenie stoi
  (`zalozenia.md`: „nie istnieją w żadnym blobie"). Różnica praktyczna: treść **zastagowana, ale
  niezacommitowana** przechodzi tu, a przy porównaniu z `HEAD` byłaby odrzucona — i słusznie
  przechodzi, bo `git add` już utrwalił blob (zweryfikowane: `git cat-file blob :ścieżka | cmp -`
  po `lock` przechodzi). Dodatkowo porównanie z `HEAD` uniemożliwiałoby `lock` w repozytorium
  bez commitów, a wersja indeksowa wyłapuje pliki nieśledzone, których `HEAD` nie widzi wcale.
- **`refuse_other_worktrees` nie było w planie.** Bez niego komenda produkuje stan, którego plan
  jawnie zakazuje; szczegóły w F2/C1/C2.
- **`lock` naprawia brakującą rejestrację filtra i brakującą linię catch-all.** Plan dał to
  zadanie wyłącznie `unlock`. Powód w F4; ograniczenie do „tylko to, czego brakuje" w W1/W2.
- **Zamiatanie sierot `*.git-xcrypt-<hex>.tmp` nie było w planie** — weszło jako odpowiedź na
  udokumentowaną resztkę po `SIGKILL` z przeglądu S-03, gdzie przy `lock` jest groźniejsza
  (plaintext przeżywa komendę, która miała go usunąć).
- **`gitindex::staged_ids` / `blob_id` oraz refaktor `walk`** — konsekwencja wyboru indeksu jako
  podstawy sprawdzenia. Ani jeden nowy crate: `gix-hash` był już w drzewie.
- **Kryterium 1.12 („tryb interaktywny w prawdziwym terminalu")** zweryfikowane przez potok
  (`xcrypt_with_stdin`), nie przez TTY. Prompt czyta `stdin`, nie `/dev/tty`, więc potok jest
  wierną repliką ścieżki kodu; zachowanie w terminalu z przekierowanym `stderr` pozostaje
  niesprawdzone empirycznie i jest udokumentowane przy `Ask`.

## Luki w weryfikacji, które zostają

- **`core.ignorecase` i normalizacja Unicode** — patrz obserwacje przebiegu 2. Kierunek błędu jest
  bezpieczny, rozjazd jest zgłaszany, ale realna naprawa to decyzja o semantyce wzorców.
  **Do rozstrzygnięcia przez człowieka**, razem z pozycją odłożoną przy S-02.
- **`unlock` ma ten sam kształt co W4** — do `forget_stat` podaje wyłącznie pliki odszyfrowane
  w danym przebiegu, więc plik odszyfrowany przez **przerwany** wcześniejszy `unlock` zostaje
  z nieaktualnym cache'em `stat`. Naprawa nie jest jednolinijkowa (przejście `unlock` zbiera
  wyłącznie pliki z naszym magic, więc już jawne w ogóle w nim nie są) i leży poza zakresem S-04.
  **Do decyzji człowieka.**
- **Windows i `core.autocrlf=true`** — jak w S-01 i S-03, wymaga nogi CI.
- **Podzielony indeks** kończy `lock` odmową (kod `2`) zamiast degradacją, w odróżnieniu od
  `unlock`. Świadome: komenda kasująca klucz nie może zgadywać. Komunikat podaje wyjście.
