<!-- IMPL-REVIEW-REPORT -->
# Przegląd implementacji: Widoczność stanu szyfrowania

- **Plan**: `context/archive/2026-08-04-encryption-status-check/plan.md`
- **Zakres**: Fazy 1–3 z 3 (wszystkie ukończone)
- **Data**: 2026-08-04
- **Werdykt**: ODRZUCONY po pierwszym przebiegu → ODRZUCONY po drugim → ZAAKCEPTOWANY
- **Ustalenia**: przebieg 1 — 3 krytyczne, 4 ostrzeżenia, 6 obserwacji;
  przebieg 2 — 2 krytyczne, 6 ostrzeżeń, 9 obserwacji
- **Metoda**: dwóch recenzentów równolegle (zgodność z planem; bezpieczeństwo,
  jakość i wzorce), plus własne sondy na prawdziwych repozytoriach git 2.55 —
  SHA-256, podzielony indeks, obiekty w paczkach, podłączony worktree,
  repozytorium bez commitów, bare, nieczytelny `packed-refs`, dowiązanie
  symboliczne, tag na blobie, zajęty `index.lock`, brakujący plik roboczy.

## Werdykty

| Wymiar | Przed naprawą | Po naprawie |
| --- | --- | --- |
| Zgodność z planem | PASS | PASS |
| Dyscyplina zakresu | PASS | PASS |
| Bezpieczeństwo i jakość | FAIL | PASS |
| Architektura | PASS | PASS |
| Spójność wzorców | PASS | PASS |
| Kryteria sukcesu | PASS | PASS |

Bramka jakości po obu przebiegach: `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings` i `cargo test` (262 testy jednostkowe
+ 130 integracyjnych, w tym 40 nowych w `tests/status_command.rs`) przechodzą.
Zestaw integracyjny uruchomiony ośmiokrotnie z rzędu bez ani jednej awarii.

## Ustalenia krytyczne

### F1 — repozytorium SHA-256 wywracało `status` **i filtr** paniką

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość
- **Lokalizacja**: `src/history.rs` (`objects`, przed naprawą `gix_odb::at`)
- **Szczegóły**: `gix_odb::at` bierze domyślny skrót, czyli SHA-1, a magazyn
  obiektów **asertuje** rodzaj skrótu każdego identyfikatora, który dostaje.
  Zmierzone w repozytorium założonym przez `git init --object-format=sha256`:

  ```
  $ git-xcrypt status
  panicked at gix-odb-0.83.0/src/store_impls/loose/find.rs:34:
  assertion `left == right` failed: left: Sha1  right: Sha256
  exit=101
  ```

  Gorsze niż sama komenda: tę samą ścieżkę otwiera `HeadLookup` **na ścieżce
  check-in**, więc panika filtra przy `required = true` przerywa *każdą*
  operację gita w takim repozytorium — `git status` kończył się kodem 128.
  `src/gitindex.rs` czyta indeksy SHA-256 od S-03, więc był to rozjazd wewnątrz
  jednego produktu.
- **Naprawa**: `history::objects(common_dir, hash)` przez `gix_odb::at_opts`
  z jawnym `object_hash`; wszystkie trzy wywołania (`status`, skan historii,
  `HeadLookup`) dostają skrót z `extensions.objectformat`.
- **Test**: `a_sha256_repository_is_scanned_and_fixed_rather_than_crashed_on`
  (pełny przebieg: skan → `--fix` → commit → ciphertext w blobie).
- **Decyzja**: NAPRAWIONE

### F2 — nieczytelne referencje dawały czyste świadectwo zdrowia

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość
- **Lokalizacja**: `src/history.rs` (`tips`), `src/commands/status.rs` (`run`)
- **Szczegóły**: każda awaria w `tips` — `store.iter()`, `platform.all()`,
  `try_find("HEAD")`, referencja, której nie da się rozwinąć — trafiała wyłącznie
  do `scan.warnings`, czyli na `stderr`, i nie ruszała `Report::exposed()`.
  `Scan::unreadable` rosło tylko przy obiektach. Skutek: magazyn referencji,
  którego nie da się przeczytać, daje **zero wierzchołków**, więc skan odwiedza
  zero commitów i nie znajduje nic. Zmierzone:

  ```
  $ chmod 000 .git/packed-refs && rm .git/refs/heads/main && git-xcrypt status
  scanned 0 commit(s) and 0 distinct blob(s) ...
  exit=0                      # a w historii leży jawny blob
  ```

  To jest dokładnie to, czego zakazuje komentarz tego modułu: „«nic nie
  znaleziono» i «nic nie znaleziono w tym, co dało się przeczytać» nigdy nie
  wyglądają tak samo". Bramka CI czyta kod wyjścia, nie `stderr`.
- **Naprawa**: `Scan::unresolved_refs` i `Scan::refs_unavailable` liczone
  osobno od obiektów; `status` zamienia oba na wpis `undetermined`, a ten
  wchodzi do `exposed()`. Awaria całego magazynu mówi wprost, że nie
  przeskanowano niczego.
- **Test**: `references_that_cannot_be_read_fail_the_gate_instead_of_reading_as_clean`.
- **Decyzja**: NAPRAWIONE

### F3 — `--fix` niszczył dowiązania symboliczne i szyfrował cudzą treść

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość
- **Lokalizacja**: `src/gitindex.rs` (`list`, `Entry`), `src/commands/status.rs`
  (`inspect_index`, `restage`)
- **Szczegóły**: `gitindex::list` zwracał `(nazwa, oid)` i **gubił tryb wpisu**.
  Blob dowiązania symbolicznego to jego cel jako tekst — nie ma magic — więc
  ścieżka była raportowana jako „w postaci jawnej", a `--fix` robił na niej
  `fs::read`, które **idzie za dowiązaniem**, szyfrował to, co znalazł po drugiej
  stronie, i przestawiał wpis, zostawiając tryb `120000`. Zmierzone:

  ```
  $ ln -s ../target.txt secrets/link.env     # target.txt nie jest zadeklarowany
  $ git-xcrypt status --fix
  fixed: 1 path(s) were re-staged ...  secrets/link.env
  $ git ls-files -s secrets/link.env
  120000 dfcfeeb5... 0	secrets/link.env
  $ git cat-file blob :secrets/link.env | xxd | head -1
  00000000: 0047 4954 5843 5259 5054 ...
  ```

  Dwie różne szkody: **(a)** komenda reklamowana jako naprawa po cichu niszczy
  śledzone dowiązanie (po klonie `link.env -> ` z pustym celem, bo ciphertext
  zaczyna się od NUL); **(b)** plaintext pliku, którego **żaden wzorzec nie
  obejmuje**, ląduje zaszyfrowany w bazie obiektów pod cudzą ścieżką.
  `history::walk_tree` miał sprawdzenie `entry.mode.is_blob()` od początku —
  dwie połówki tego samego produktu odpowiadały inaczej na to samo pytanie.
- **Naprawa**: `walk` wyciąga tryb (offset 24..28 wpisu), `Listed::Read` niesie
  `Tracked { path, id, mode }` z `is_regular_file()`, a `inspect_index` pomija
  wszystko, co nie jest zwykłym plikiem — tak jak `walk_tree`.
- **Test**: `a_tracked_symlink_is_left_alone_by_fix`.
- **Decyzja**: NAPRAWIONE

## Ostrzeżenia

### F4 — nieaktualny cache drzewa cofał `--fix` przy commicie

- **Ważność**: ❌ KRYTYCZNE (znalezione i naprawione w trakcie Fazy 3, przed
  przeglądem) · **Lokalizacja**: `src/gitindex.rs` (`restage`)
- **Szczegóły**: rozszerzenie `TREE` indeksu zapamiętuje obiekt drzewa każdego
  katalogu, a git mu ufa. Przestawienie wpisu na nowy blob bez unieważnienia go
  dawało `git diff-index --cached HEAD` **bez żadnej różnicy**, a następny
  `git commit` zapisywał stare drzewo — czyli plaintext wracał do bazy obiektów
  z komendy, która przed chwilą zgłosiła naprawę. Zmierzone na git 2.55.
- **Naprawa**: `restage` odbudowuje sekcję rozszerzeń bez `TREE` (który
  unieważnia) i bez `EOIE` (który niesie skrót po nagłówkach rozszerzeń).
  `IEOT`, `REUC`, `UNTR` i stan fsmonitora zostają — opisują rzeczy, których ta
  edycja nie ruszyła.
- **Test**: `every_index_version_survives_a_restage_and_git_commits_the_new_blob`
  (wersje 2/3/4, z commitem i sprawdzeniem zapisanego bloba).
- **Decyzja**: NAPRAWIONE

### F5 — tag wskazujący na coś, co nie jest commitem, zapalał bramkę na stałe

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/history.rs` (`tips`)
- **Szczegóły**: `peel_to_id` na tagu blobowym daje identyfikator bloba, który
  trafiał do kolejki commitów; `find_commit_iter` zawodził i `note_unreadable`
  liczyło to jako uszkodzony obiekt. Tag na blobie to realny wzorzec —
  `junio-gpg-pub` w git.git. Zdrowe repozytorium dostawało trwale czerwoną
  bramkę z radą `git fsck`, która nie zgłosiłaby niczego.
- **Naprawa**: `tips` sprawdza rodzaj obiektu przez `try_header` i pomija
  po cichu wszystko, co nie jest commitem.
- **Test**: `a_tag_on_something_that_is_not_a_commit_does_not_fail_the_gate`.
- **Decyzja**: NAPRAWIONE

### F6 — `restage` raportował liczbę zamiast nazw

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/gitindex.rs`,
  `src/commands/status.rs`
- **Szczegóły**: `Outcome::Cleared(n)` mówi **ile**, nie **które**, a `edits`
  powstaje w kolejności indeksu, gdy `updates` jest w kolejności raportu. Przy
  krótszej liczbie kod robił `truncate(count)`, więc sekcja `fixed:` mogła
  wymienić ścieżkę, której nie ruszono, a prawdziwa znikała również z
  `in_the_clear`. Kierunek awarii był bezpieczny (`undetermined` i tak zapalało
  bramkę), ale raport nie był prawdziwy.
- **Naprawa**: `Restaged::Done(Vec<Vec<u8>>)` z nazwami; wszystko, o co pytano
  i co nie wróciło, zostaje w `in_the_clear` i jest wymienione w ostrzeżeniu.
- **Test**: `a_restage_reports_which_paths_it_patched_not_how_many`.
- **Decyzja**: NAPRAWIONE

### F7 — cache pytania o `HEAD` pamiętał tylko odpowiedzi twierdzące

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/filter.rs`
- **Szczegóły**: wpis do zbioru następował wyłącznie przy `found == true`, więc
  w repozytorium **zdrowym** — gdzie odpowiedź brzmi zawsze „nie" — każde
  kolejne `clean` tej samej ścieżki ponownie przechodziło po drzewach i
  **rozpakowywało cały blob z `HEAD`**, żeby przeczytać 11 bajtów. Własny test
  projektu zapisuje, że jedno `git status` filtruje tę samą ścieżkę cztery razy.
- **Naprawa**: `HashMap<Vec<u8>, bool>` zamiast `HashSet` — `true` tłumi
  powtórzony komunikat, `false` tłumi powtórzoną pracę.
- **Decyzja**: NAPRAWIONE

### F8 — ścieżka robocza budowana ze stratnie zdekodowanego napisu

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/status.rs` (`restage`)
- **Szczegóły**: `repo.work_tree().join(Path::new(&show(&name)))`, gdzie `show`
  to pomocnik **do wypisywania**, którego własny komentarz mówi, że ścieżki
  decyzyjne trzymają bajty. Na Uniksie nazwa pliku to dowolny ciąg bajtów, więc
  każdy bajt spoza UTF-8 stawał się U+FFFD i `fs::read` otwierał plik, którego
  nie ma. To ta sama klasa błędu, którą przegląd S-01 znalazł na ścieżce filtra
  (F2 tamtego przeglądu).
- **Naprawa**: `working_tree_path` przez `OsStr::from_bytes` na Uniksie.
- **Test**: `a_working_tree_path_is_built_from_bytes_not_from_a_decoded_string`
  (jednostkowy — APFS na macOS odmawia założenia pliku o nazwie spoza UTF-8,
  więc dowód end-to-end wymaga nogi CI na Linuksie; ta sama luka co w S-01).
- **Decyzja**: NAPRAWIONE

## Obserwacje

### F9 — nieurodzona gałąź raportowana jako awaria

- **Lokalizacja**: `src/history.rs` (`tips`)
- **Szczegóły**: między `git init` a pierwszym commitem `HEAD` jest symboliczny
  i wskazuje na nieistniejącą gałąź. `peel_to_id` zawodził, więc **każde** świeże
  repozytorium witało użytkownika komunikatem „HEAD: not scanned, it could not
  be resolved".
- **Naprawa**: symboliczna referencja, której cel nie istnieje, jest pomijana bez
  słowa. **Test**: `a_repository_with_no_commits_yet_reports_nothing_alarming`.
- **Decyzja**: NAPRAWIONE

### F10 — `--fix` bez klucza wyrzucał całą diagnozę

- **Lokalizacja**: `src/commands/status.rs` (`restage`)
- **Szczegóły**: `repo.load_key()?` propagował `NoKey` po wykonaniu całej pracy,
  więc użytkownik, który dopisał jedną flagę za dużo, dostawał mniej informacji
  niż bez niej — tracił sekcję konfiguracji i cały skan historii.
- **Naprawa**: brak klucza to wpis `undetermined` z odesłaniem do `unlock`;
  raport wychodzi w całości, kod `5`. **Test**:
  `fix_without_a_key_says_so_without_throwing_the_report_away`.
- **Decyzja**: NAPRAWIONE

### F11 — budżet ostrzeżeń dzielony z komunikatami o referencjach

- **Lokalizacja**: `src/history.rs` (`note_unreadable`)
- **Szczegóły**: limit sprawdzał `scan.warnings.len()`, w którym siedzą już
  komunikaty o referencjach, więc pięć złych referencji sprawiało, że żaden
  uszkodzony obiekt nie zostawał nigdy nazwany.
- **Naprawa**: budżet liczony po `scan.unreadable`. **Decyzja**: NAPRAWIONE

### F12 — cytowanie ścieżki w wypisywanym poleceniu `git-filter-repo`

- **Lokalizacja**: `src/commands/status.rs`
- **Szczegóły**: `--path '{}'` bez ucieczki — plik o nazwie `it's.env` dawał
  polecenie, które powłoka parsuje inaczej, niż wygląda. Raport jest tylko
  wypisywany, nigdy wykonywany, więc to kwestia niewręczania użytkownikowi
  zepsutej instrukcji, nie wstrzyknięcia.
- **Naprawa**: `shell_quoted`, ta sama ucieczka co w `init::current_executable`.
  **Test**: `a_quote_in_a_path_does_not_break_the_command_the_report_hands_out`.
- **Decyzja**: NAPRAWIONE

### F13 — nieograniczony stan skanu

- **Lokalizacja**: `src/history.rs`
- **Szczegóły**: `seen_trees` trzyma wpis na parę `(drzewo, ścieżka)` w całej
  osiągalnej historii, z klonowaną ścieżką; `queue` może urosnąć do liczby
  krawędzi commitów. Brak limitu, paska postępu i sposobu przerwania.
  Zmierzone: 51 commitów × 400 plików → 0,3 s, więc dla zwykłych repozytoriów
  jest to nieistotne.
- **Decyzja**: ZAAKCEPTOWANE — zapisane w komentarzu modułu wraz z tanim
  usprawnieniem, gdyby kiedyś uwierało (internowanie prefiksów).

### F14 — osierocone obiekty po pominiętym łataniu indeksu

- **Lokalizacja**: `src/commands/status.rs` (`restage`)
- **Szczegóły**: blob ciphertextu powstaje przed wzięciem blokady indeksu, więc
  przy zajętym `index.lock` zostaje w bazie jako obiekt nieosiągalny. Nieszkodliwe
  (`git gc` go zbiera), ale „nic nie przestawiono" nie znaczy „nic nie zapisano".
- **Decyzja**: ZAAKCEPTOWANE — udokumentowane przy funkcji.

### F15 — ścieżka w trakcie scalania niewidoczna dla części indeksowej

- **Lokalizacja**: `src/gitindex.rs` (`list` filtruje do stage 0)
- **Szczegóły**: zadeklarowana ścieżka z nierozwiązanym konfliktem nie trafia
  ani do `encrypted`, ani do `in_the_clear`, ani do `undetermined`. Skan
  historii i tak widzi bloby stron konfliktu, bo pochodzą z commitów, więc nie
  jest to fałszywe przejście — brakuje wyłącznie zdania o tym, co zapisze
  **następny** commit, a to jest naprawdę nierozstrzygnięte do czasu scalenia.
- **Decyzja**: ZAAKCEPTOWANE — udokumentowane w komentarzu modułu.

## Potwierdzone jako poprawne

- **Bajtowe łatanie indeksu w `restage`** prześledzone osobno: granice
  (`walk` weryfikuje `flags_at + 2 <= body.len()`, a `SIZE_FIELD + 4 == ID_FIELD`),
  wersje 2/3/4 wraz z dopełnieniem v2/v3 i kompresją prefiksową v4, nasycenie
  `0x0fff`, SHA-256 przez całą ścieżkę, `index.skipHash`, dyscyplina blokady na
  każdym wyjściu, brak osiągalnego stanu częściowego zapisu (zapis idzie do
  `index.lock` i jest przemianowany). Odrzucenie `EOIE` bezpieczne: bez niego
  `read_eoie_extension` zwraca 0, git schodzi na jeden wątek i ignoruje `IEOT`.
- **Reguły twarde**: zero `unsafe`, brak `unwrap`/`expect`/`panic!` poza testami
  w nowych modułach, `stdout` pusty na każdej ścieżce błędu, żaden materiał
  klucza ani treść pliku nie trafia do wyjścia (raport wypisuje wyłącznie
  ścieżki, identyfikatory obiektów i liczby), plaintext czytany przez `--fix`
  owinięty w `Zeroizing`.
- **Zgodność ze wzorcami**: rozdział „przeczytane / niedostępne" w
  `Listed`/`Staged`/`Restaged` spójny; ostrzeżenia wynoszone do binarki jak w
  `lock` i `unlock`; przechył „ostrzegaj i zostaw w `in_the_clear`" właściwy dla
  komendy raportującej, w odróżnieniu od „odmawiaj przy wątpliwości" w `lock`.

## Ustalenia świadomie odrzucone

- **`gitconfig::is_true` miało zmienić zachowanie ścieżki smudge** (rzekomo
  `TRUE` czytane wcześniej jako fałsz). **Nie potwierdzone**: `eol::resolve_output`
  robi `to_ascii_lowercase` **przed** wywołaniem, więc wyodrębnienie funkcji jest
  zachowawcze. Sprawdzone w kodzie (`src/eol.rs:147`).
- **Testy 3.4/3.5 uznane za niestabilne przez recenzenta.** Nie potwierdzone jako
  wada produktu: awaria wystąpiła, gdy binarka była w tym czasie przebudowywana.
  Zestaw uruchomiony ośmiokrotnie z rzędu w spokojnym drzewie — 32/32 za każdym
  razem. Fikstura została mimo to utwardzona (plik jest przepisywany, więc
  `stat` na pewno się nie zgadza), a **prawdziwa luka, którą recenzent przy
  okazji odsłonił, dostała własny test** — patrz niżej.
- **`status` w repozytorium bare** kończy się kodem `2` („to jest repozytorium
  bare"), bo tak działa `Repo::discover` dla wszystkich komend. Skanowanie
  historii po stronie serwera byłoby użyteczne jako bramka CI, ale to
  poszerzenie zakresu i decyzja człowieka.

## Luka w produkcie odsłonięta przy okazji, udokumentowana i pokryta testem

**Dopisanie wzorca do `.git-xcrypt` nie sięga pliku, który już jest
zacommitowany i którego nikt potem nie zmienił.** Filtr czyta deklarację przy
każdym wywołaniu, ale git decyduje z **cache'u `stat`**, czy w ogóle go wywołać.
Zmierzone na git 2.55, poza oknem racy-clean:

```
git add -A && git commit               # zanim wzorzec powstał
printf 'secrets/\n' > .git-xcrypt
git add -A && git commit               # kod 0, żadnego ostrzeżenia
git cat-file blob HEAD:secrets/db.env  → hunter2
```

Zdanie z `zalozenia.md` „Dopisanie wzorca działa natychmiast, bez żadnej komendy
synchronizującej" jest więc prawdziwe o filtrze i **nieprawdziwe o gicie**.
Nic w tej sekwencji nie jest z punktu widzenia gita błędem i nic o niej nie mówi.

To jest najmocniejszy argument za istnieniem `--fix` w obecnym kształcie i za
tym, że operuje na indeksie zamiast wypisywać radę: `status` wykrywa ten stan
(`in the clear` + `leaked in history`, kod `5`), a `--fix` go naprawia.
Udokumentowane w nagłówku `src/commands/status.rs`, pokryte testem
`a_declaration_added_later_does_not_reach_an_untouched_file_and_status_says_so`.

**Do decyzji człowieka:** czy dopisać to ograniczenie do `zalozenia.md`
§Integracja z git obok pozostałych zmierzonych zachowań gita. Wpisane już do
`AGENTS.md` jako twarda reguła, bo następny agent musi je znać.

## Rozjazdy planu wobec stanu kodu

Odnotowane, nie naprawiane w planie:

- **Faza 1 miała sprawdzać `diff.git-xcrypt.textconv` jako część kompletności.**
  Kod tego nie robi i ma to udokumentowane: `lock` **celowo** wyrejestrowuje
  sterownik diff, więc liczenie go jako braku sprawiłoby, że każde poprawnie
  zamknięte repozytorium zgłasza się jako zepsute. Brak sterownika kosztuje
  czytelny `git diff` i nic więcej. Zamiast tego jest nota niewpływająca na kod
  wyjścia, wypisywana tylko tam, gdzie jest wykonalna (repozytorium z kluczem).
  Zgodne z `gitattributes::driver_keys()`, które już od S-01 miało dwa elementy
  przygotowane właśnie dla `status`.
- **Faza 3 mówi „szyfrowane w miejscu", `zalozenia.md` mówi „ponownie dodane".**
  Kod idzie za `zalozenia.md`: czyta plik roboczy, przepuszcza przez
  `decide::clean`, zapisuje blob i przestawia wpis indeksu — **katalog roboczy
  zostaje nietknięty**. Szyfrowanie w miejscu to zadanie `lock`; robienie tego
  tutaj odebrałoby użytkownikowi jego własne sekrety w imię naprawy.
- **Faza 3 wskazuje `src/decide.rs` na ostrzeżenie przy pierwszym szyfrowaniu.**
  Leży w `src/filter.rs` + `src/history.rs`, bo odpowiedź wymaga bazy obiektów i
  uchwytu repozytorium, a `decide::clean` jest czystą funkcją treści — i `lock`
  polega na tym, że pozostanie. Powód zapisany przy `decide::clean`.
- **`--fix` czyta indeks, nie `HEAD`.** Plan mówi „w katalogu roboczym lub
  `HEAD`". Indeks jest pytaniem z lekarstwem: to on mówi, co zapisze następny
  commit, i to `git add` go naprawia. `HEAD` pokrywa skan historii.
- **`gitindex` urósł o `list`, `restage`, `Tracked`, `Restaged` i refaktor
  `walk` na `Walked`/`Extension`.** Konsekwencja `--fix`; cały byłby niemożliwy
  bez wywołania `git`, czego zabrania wymóg samowystarczalnej binarki.
- **Nowe zależności**: `gix-odb` (0.83), `gix-object` (0.63), `gix-ref` (0.66).
  Dwie ostatnie były już w drzewie przez `gix-discover`, więc realnie doszło
  dziewięć paczek: `gix-odb`, `gix-pack`, `gix-chunk`, `gix-quote`, `gix-zlib`,
  `zlib-rs`, `arc-swap`, `crc32fast`, `rustversion`. Wszystkie
  `MIT OR Apache-2.0` poza `zlib-rs`, które ma licencję **Zlib** — permisywną,
  zatwierdzoną przez OSI, bez copyleft, więc `MIT OR Apache-2.0` projektu
  zostaje w mocy. Do wpisania w przyszłą konfigurację `cargo deny`.

## Drugi przebieg — czego pierwszy nie dotknął

Metoda: dwóch recenzentów równolegle na zbudowanej binarce — jeden polował na
regresje po naprawach z przebiegu pierwszego, drugi na treść raportu jako
zabezpieczenie, na zgodność z pozostałymi komendami i na kontrakt kodów wyjścia.
Wszystkie osiem napraw z przebiegu 1 **potwierdzono jako poprawne**, w tym
bajtowe łatanie indeksu na wersjach 2/3/4, SHA-256, `index.skipHash` oraz — po
raz pierwszy — na indeksie z 3001 wpisami, gdzie rozszerzenia `EOIE` i `IEOT`
faktycznie występują; git przyjął przebudowany plik, `TREE` i `EOIE` zniknęły,
`IEOT` został.

### G1 — `--fix` wyrzucał cały raport przez jeden plik, którego nie umiał wyczyścić

- **Ważność**: ❌ KRYTYCZNE · **Lokalizacja**: `src/commands/status.rs` (`restage`)
- **Szczegóły**: `decide::clean(...)?` propagował błąd, więc plik zaszyfrowany
  obcym kluczem przerywał całą komendę. Zmierzone: `status` bez `--fix` dawał
  kod `5` i dwie ścieżki w historii; `status --fix` na tym samym repozytorium
  dawał **kod `4`, zero bajtów na `stdout`** i ani jednego znaleziska. Bramka
  czytała „narzędzie się zepsuło". Dwie awarie po obu stronach tej linii —
  nieczytalny plik i nieudany zapis obiektu — były obsłużone poprawnie od
  początku; ta jedna była wyjątkiem.
- **Naprawa**: ostrzeżenie, ścieżka zostaje w `in_the_clear`, przebieg trwa dalej.
- **Decyzja**: NAPRAWIONE

### G2 — zielony raport na repozytorium, którego git nie filtruje

- **Ważność**: ❌ KRYTYCZNE · **Lokalizacja**: `src/gitattributes.rs`,
  `src/commands/status.rs`
- **Szczegóły**: dwa niezależne warianty tej samej luki.
  **(a)** `catch_all_present` szuka dosłownej linii, a git bierze **ostatnie**
  dopasowanie — linia `secrets/** -filter` poniżej sekcji zarządzanej wyłącza
  filtr dla zadeklarowanych ścieżek. Zmierzone: `git check-attr filter` mówi
  `unset`, `git add` zapisuje plaintext, a `status` mówił, że wszystko gra.
  **(b)** `.gitattributes` i `.git-xcrypt` czytane są z katalogu roboczego i
  nikt nie pytał, czy są **śledzone**. `init` je tworzy i nie commituje, więc
  repozytorium wypchnięte bez nich wygląda od środka na skonfigurowane, a każdy
  jego klon nie filtruje niczego.
- **Naprawa**: (b) to nowa luka konfiguracji `SetupGap::Untracked`, zapalająca
  bramkę — ale dopiero gdy cokolwiek innego jest już śledzone, żeby nie czepiać
  się repozytorium sprzed pierwszego `git add`. (a) to **nota**, nie luka:
  odpowiedź „które ścieżki to naprawdę obejmuje" wymaga przejścia stosu
  atrybutów gita (`gix-attributes` plus zagnieżdżone pliki), a `filter=lfs` na
  niezwiązanych ścieżkach jest zupełnie legalne i nie może palić bramki. Nota
  nazywa linie i odsyła do `git check-attr`.
- **Testy**: `bootstrap_files_that_were_never_committed_are_a_setup_gap`,
  `a_line_that_turns_the_filter_off_is_named`.
- **Decyzja**: NAPRAWIONE częściowo — pełne rozstrzyganie atrybutów **wymaga
  decyzji człowieka**, patrz „Do decyzji człowieka" niżej.

### G3 — raport chował to, po co się go czyta

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/status.rs` (`Display`)
- **Szczegóły**: sekcja „encrypted" wypisywała **każdą** zadeklarowaną ścieżkę i
  szła **przed** sekcjami o ekspozycji. Zmierzone przy 301 ścieżkach i jednym
  wycieku: 319 linii, `leaked in history` w linii 306, `ROTATE THE SECRET` w 312.
  Na czterdziestoliniowym terminalu użytkownik widzi ścianę dobrych wiadomości i
  nic więcej. Polecenie `git filter-repo` z 301 argumentami `--path` było jedną
  nieprzeklejalną linią.
- **Naprawa**: linia `VERDICT:` na samej górze, lista „encrypted" ucięta do
  dziesięciu pozycji, szczegóły blobów ucięte do trzech na ścieżkę, a polecenie
  rewrite'u powyżej dziesięciu ścieżek przechodzi na `--paths-from-file`.
- **Testy**: `the_verdict_comes_before_the_wall_of_good_news`,
  `a_clean_repository_says_so_on_its_first_line`.
- **Decyzja**: NAPRAWIONE

### G4 — raport przeczył sam sobie po nieudanym `--fix`

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/status.rs` (`Display`)
- **Szczegóły**: trzy warianty. `stdout` po `--fix`, który jednej ścieżki nie
  ruszył, radził uruchomić `--fix` — czyli komendę, której wynik czytelnik trzyma
  w ręku — a powód leżał wyłącznie na `stderr`. Checklista historii kazała zrobić
  `--fix` również wtedy, gdy `--fix` właśnie odmówił. Linia zamykająca mówiła
  „scanned 0 commit(s)" w repozytorium z pięciuset commitami, gdy przebieg wrócił
  przed skanem.
- **Naprawa**: `Report::fix_requested` i `Report::scan_ran`; rady są warunkowe,
  a brak skanu jest nazwany zamiast wyliczony na zero.
- **Decyzja**: NAPRAWIONE

### G5 — `--fix` zastawiał niezastagowane zmiany i twierdził inaczej

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/status.rs`
- **Szczegóły**: `restage` czyta **katalog roboczy**, więc `--fix` zastawia też
  edycje, których użytkownik świadomie nie zastagował — dokładnie tak jak
  `git add`, i to jest właściwe zachowanie. Raport mówił jednak „This changed the
  index and nothing else … The working tree is untouched … commit when ready",
  co zaprasza do zacommitowania czegoś, o czym nie wspomniano.
- **Naprawa**: raport mówi wprost, że zastawiona jest treść z katalogu roboczego,
  edycje niezastagowane włącznie, i odsyła do `git diff --cached`.
- **Decyzja**: NAPRAWIONE

### G6 — plik pod `refs/`, który nie jest referencją, palił bramkę

- **Ważność**: ⚠️ OSTRZEŻENIE (regresja naprawy F2) · **Lokalizacja**: `src/history.rs` (`tips`)
- **Szczegóły**: naprawa F2 liczyła jako nierozwiązaną referencję również błąd
  **iteracji**, który obejmuje pusty plik po awarii albo przypadkowy `notes.txt`
  w `refs/heads/`. Git wypisuje `warning: ignoring broken ref` i idzie dalej,
  bo taki plik nie prowadzi do żadnej historii. Zmierzone: `git status` kod 0,
  `git-xcrypt status` kod 5.
- **Naprawa**: błąd iteracji to nota (tolerancja gita), błąd **rozwinięcia** —
  czyli referencja, która nią jest i nie prowadzi nigdzie — nadal pali bramkę,
  bo tam git też umiera. Dodatkowo nazwy referencji trafiają na `stdout`;
  wcześniej `stdout` mówił „1 reference(s)", a nazwa była tylko na `stderr`.
- **Testy**: `a_file_under_refs_that_is_not_a_reference_does_not_fail_the_gate`,
  `a_reference_that_will_not_resolve_is_named_not_merely_counted`.
- **Decyzja**: NAPRAWIONE

### G7 — klon częściowy raportowany jako uszkodzony

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/status.rs`
- **Szczegóły**: bliźniak naprawionego wcześniej klonu płytkiego. Obiekt
  promisor jest nieobecny z założenia, a raport mówił „N object(s) could not be
  read … `git fsck` says what is missing" — przy czym `git fsck` w klonie
  częściowym kończy się zerem i nie zgłasza nic.
- **Naprawa**: wykrycie po `remote.<nazwa>.promisor` / `extensions.partialclone`
  i własny wpis `undetermined` z poleceniem, które faktycznie pomaga.
- **Decyzja**: NAPRAWIONE

### G8 — `git add -N` raportowany jako naprawiony

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/gitindex.rs`, `src/commands/status.rs`
- **Szczegóły**: wpis intent-to-add ma tryb `100644` i pusty blob, więc czytał
  się jako treść jawna; `--fix` przestawiał go i ogłaszał naprawę, której
  następny `git commit` nie robi — git nadal traktuje ścieżkę jako niezastagowaną.
- **Naprawa**: `Tracked::intent_to_add` z rozszerzonego słowa flag (bit `0x2000`,
  czyli `CE_INTENT_TO_ADD`), pomijany razem z dowiązaniami i gitlinkami.
- **Test**: `an_intent_to_add_entry_is_not_claimed_as_fixed`.
- **Decyzja**: NAPRAWIONE

### Obserwacje z drugiego przebiegu, naprawione

- **Nieczytelny `HEAD` twierdził, że nic nie przeskanowano** — flaga
  `refs_unavailable` była ustawiana z trzech różnych awarii, a czytana jako
  jedna; raport przeczył liczbie commitów trzy linie niżej. Teraz to jedna
  nierozwiązana referencja.
- **`--fix` gubił ostrzeżenie z `decide::clean`** — druga implementacja ścieżki
  check-in nie może być tą, która połyka komunikat.
- **`--fix` wyrzucał raport przy każdym błędzie klucza poza `NoKey`** — nieczytelny
  plik klucza tracił diagnozę tak samo jak brakujący.
- **Budżet ostrzeżeń o referencjach** — obiekty dostały swój przy F11, referencje
  nie miały żadnego; tysiąc zepsutych referencji zalewało `stderr`.
- **Referencja wskazująca na drzewo lub blob znikała bez śladu** — teraz nota.
- **Kody wyjścia**: błąd użycia kończył się kodem `2`, tym samym co „konflikt
  stanu" — bramka nie odróżniłaby literówki od zepsutego repozytorium; teraz `1`,
  a `--help` i `--version` kończą się zerem. Nieczytelny `.gitattributes` kończył
  się kodem `1` wbrew własnemu kontraktowi funkcji; teraz `2`.
- **Nieaktualna sekcja `.gitattributes`** — `sync --check` kończył się jedynką,
  a `status` zerem i milczeniem na tym samym repozytorium. Teraz nota, nie luka:
  linie kosmetyczne to zadanie `sync` i ich rozjazd nigdy nie zapisuje sekretu
  jawnie, ale klon takiego repozytorium po `unlock` ma brudny `git status`,
  wbrew kryterium akceptacji 6.
- **Repozytorium zamknięte czytało się identycznie jak zdrowe** — teraz nota
  mówiąca, że klucza tu nie ma.

### Potwierdzone jako poprawne w drugim przebiegu

- **Wszystkie osiem napraw z przebiegu 1**, prześledzone osobno i w większości
  empirycznie: `at_opts` (jedyna różnica wobec `at` to `object_hash`), offset
  trybu 24..28 niezależny od wersji indeksu i długości skrótu, `Restaged::Done`
  na obu gałęziach awarii, cache `HeadLookup` nadal wypisujący ostrzeżenie,
  pomijanie tagów na nie-commitach bez gubienia niczego legalnego (sprawdzone na
  szesnastu kształtach repozytorium), `working_tree_path`, `shell_quoted`.
- **Brak paniki, zawieszenia, uszkodzenia indeksu i fałszywego „czysto"** na:
  SHA-256, wersjach indeksu 2/3/4, podzielonym indeksie, indeksie z 3001 wpisami
  z `EOIE`/`IEOT`, obciętym i uszkodzonym indeksie, zajętym `index.lock`,
  dowiązaniu, gitlinku, konflikcie scalania, `git add -N`, podłączonym worktree,
  bisekcji, stashu, notes, `refs/replace`, alternatywach, klonie płytkim i
  częściowym, uszkodzonym `packed-refs`, nieczytelnym `refs/heads`, nieurodzonej
  gałęzi, `--orphan`, wzorcu `*` jako całej deklaracji i podwójnym `--fix`.
- **Zgodność z pozostałymi komendami**: `status` daje `0` po `init`+commicie, po
  `sync`, po `lock` i po `unlock`; `status --fix` nie psuje późniejszego `lock`;
  samo `status` nie zmienia ani jednego bajtu na dysku (sprawdzone sumami).
- **Higiena**: brak `unwrap`/`expect`/`panic!` poza testami, zero `unsafe`, ani
  jedno okno ośmiu bajtów pliku klucza ani żaden plaintext nie pojawia się w
  wyjściu (sprawdzone wprost).

## Do decyzji człowieka

1. **Pełne rozstrzyganie atrybutów.** `status` nazywa dziś linie `filter` spoza
   sekcji zarządzanej, ale nie odpowiada, których ścieżek naprawdę dotyczą.
   Odpowiedź wymaga `gix-attributes` (sprawdzone: **zero** nowych zależności
   przechodnich, wszystko już jest w drzewie) plus stosu plików `.gitattributes`
   per katalog. To jedyna znana droga do zielonego raportu na repozytorium,
   którego git nie filtruje.
2. **Klon płytki pali bramkę, a `actions/checkout` domyślnie robi klon płytki.**
   Uczciwe: historii, której nie pobrano, nie da się zaświadczyć. Praktyczne:
   każdy domyślny przebieg CI będzie czerwony, co jest najszybszą drogą do
   nauczenia ludzi ignorowania tej komendy. Do rozstrzygnięcia razem z
   dokumentacją (`fetch-depth: 0`).
3. **Kod `5` obejmuje dziś także „nie dało się ustalić".** Zamrożona tabela
   rezerwuje `5` dla ekspozycji. Fail-closed jest właściwy, ale bramka nie
   odróżni „sekret jest w historii" od „nie przeczytałem indeksu". Albo
   poszerzyć opis `5` w `zalozenia.md`, albo rozdzielić na `2`.
4. **Repozytorium bare jest odmawiane**, choć skan historii nie potrzebuje
   katalogu roboczego, a lustro bare to naturalne miejsce na bramkę serwerową.
5. **Ograniczenie cache'u `stat`** (patrz niżej) — czy dopisać je do
   `zalozenia.md` §Integracja z git obok pozostałych zmierzonych zachowań gita.

## Luki w weryfikacji, które zostają

- **Ścieżki spoza UTF-8** — APFS na macOS odmawia ich utworzenia, więc naprawa
  F8 jest pokryta wyłącznie testem jednostkowym konwersji. Ta sama luka co
  w S-01 i S-03; dowód empiryczny wymaga nogi CI na Linuksie.
- **Windows** — `restage` i `HeadLookup` nie były uruchomione na Windows;
  `working_tree_path` ma tam gałąź `from_utf8_lossy`, bo nazwy plików są UTF-16
  i bezstratnej drogi bajtowej nie ma.
- **Kryterium ręczne 3.9** — czy `stderr` filtra jest wystarczająco widoczny
  w oknie Git w JetBrains. Nie da się sprawdzić automatycznie; pozostaje
  **nierozstrzygnięte** i wymaga człowieka przy otwartym RustRoverze.
- **Bardzo duże repozytoria** — zmierzone tylko do 51 commitów × 400 plików.
  Brak limitu i paska postępu jest zapisany, nie usunięty.
