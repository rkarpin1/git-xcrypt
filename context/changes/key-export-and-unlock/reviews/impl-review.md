<!-- IMPL-REVIEW-REPORT -->
# Przegląd implementacji: Eksport klucza i odblokowanie po klonie

- **Plan**: `context/changes/key-export-and-unlock/plan.md`
- **Zakres**: Fazy 1–2 z 2 (obie ukończone)
- **Data**: 2026-08-04
- **Werdykt**: ODRZUCONY po pierwszym przebiegu → ODRZUCONY po drugim → ZAAKCEPTOWANY
- **Ustalenia**: przebieg 1 — 1 krytyczne, 6 ostrzeżeń, 7 obserwacji;
  przebieg 2 — 2 krytyczne, 2 ostrzeżenia, 4 obserwacje
- **Przebiegi**: dwa. Drugi nie był formalnością: znalazł **dwie drogi do jawnego sekretu**,
  których pierwszy nie dotknął, oraz jedno poszerzenie zasięgu wprowadzone przez naprawę
  z pierwszego przebiegu (H1)

## Werdykty

| Wymiar | Przed naprawą | Po naprawie |
| --- | --- | --- |
| Zgodność z planem | PASS | PASS |
| Dyscyplina zakresu | WARNING | PASS |
| Bezpieczeństwo i jakość | FAIL | PASS |
| Architektura | PASS | PASS |
| Spójność wzorców | PASS | PASS |
| Kryteria sukcesu | PASS | PASS |

Bramka jakości po naprawach: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
i `cargo test` (189 + 52 testów) przechodzą.

## Ustalenie krytyczne

### F1 — plik tymczasowy zapisu atomowego dało się podstawić dowiązaniem

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/atomic.rs:82,144` (przed naprawą)
- **Szczegóły**: `replace()` składało **przewidywalną** nazwę `<plik>.git-xcrypt-<pid>.tmp` i otwierało ją
  przez `fs::File::create` — czyli `O_WRONLY|O_CREAT|O_TRUNC`, bez `O_EXCL` i bez `O_NOFOLLOW`. Tą samą
  ścieżką idzie **klucz główny**: `export-key` → `keyfile::write_portable` → `write_owner_only`.

  Scenariusz: `git-xcrypt export-key /tmp/repo.key` na współdzielonej maszynie. Atakujący z prawem zapisu
  do `/tmp` tworzy wcześniej `/tmp/repo.key.git-xcrypt-<pid>.tmp` jako dowiązanie symboliczne do wybranej
  przez siebie ścieżki. `File::create` idzie za dowiązaniem, `set_permissions(0600)` przechodzi (plik jest
  nasz), `write_all` kładzie tam klucz główny, a `rename` przenosi **dowiązanie** na miejsce docelowe.
  Klucz ląduje tam, gdzie chciał atakujący, a wskazany plik użytkownika zostaje nadpisany. PID zgaduje się
  tanio. Drugi, mniejszy wariant tej samej wady: `write_owner_only` tworzyło plik z `0666 & ~umask`
  i zawężało go **po** otwarciu, więc deskryptor otwarty w tym oknie zachowywał dostęp do klucza.
- **Naprawa**: `create_new(true)` (czyli `O_EXCL` — nigdy nie otwiera niczego, co już istnieje, dowiązania
  włącznie), nazwa z 8 losowych bajtów z `getrandom` zamiast PID-u, do ośmiu prób przy kolizji, oraz
  `mode(0o600)` już przy tworzeniu dla materiału klucza. `gitindex.rs` robił to poprawnie od początku;
  `atomic.rs` nie.
- **Testy**: `a_temporary_file_never_reuses_a_name_and_never_opens_an_existing_one`,
  `a_key_temporary_is_owner_only_before_any_content_reaches_it`.
- **Decyzja**: NAPRAWIONE

## Ostrzeżenia

### F2 — przy `core.splitIndex` naprawa cache'u stat po cichu nie robiła nic

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/gitindex.rs:115` (przed naprawą)
- **Szczegóły**: zmierzone na git 2.55 na prawdziwym klonie z `core.splitIndex=true`: `unlock` kończył się
  sukcesem, **bez żadnego ostrzeżenia**, a `git status --porcelain` zwracał `" M secrets/db.env"` przy
  każdym kolejnym uruchomieniu. Przy podzielonym indeksie wpisy leżą w `.git/sharedindex.<oid>`, a `.git/index`
  trzyma rozszerzenie `link` i wpisy zastępcze o pustych nazwach — przejście po wpisach nic nie dopasowywało,
  `fields.is_empty()`, wynik `Cleared(0)`, nie do odróżnienia od „tych ścieżek nie ma w indeksie".
  To dokładnie ta awaria, przed którą ten moduł istnieje, wchodząca drzwiami, których moduł nie sprawdzał.
  `core.splitIndex` nie jest domyślne, ale włącza je hurtem `features.manyFiles=true`, zalecane przez
  dokumentację gita dla dużych repozytoriów.
- **Naprawa**: po przejściu po wpisach dochodzi przejście po **rozszerzeniach**; wykrycie sygnatury `link`
  daje `Outcome::Skipped` z komunikatem nazywającym podzielony indeks. Pusty wynik bez `link` nadal znaczy
  „te pliki nie są śledzone" i słusznie nie generuje ostrzeżenia.
- **Test**: `a_split_index_is_refused_out_loud_instead_of_quietly_doing_nothing`.
- **Decyzja**: NAPRAWIONE

### F3 — indeks czytany poza blokadą, zapisywany pod blokadą

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/gitindex.rs:67` vs `:129` (przed naprawą)
- **Szczegóły**: `fs::read` w linii 67, `index.lock` dopiero w `replace_under_lock`. Cokolwiek git zapisał
  do `.git/index` pomiędzy — `git add` w drugim terminalu, odświeżenie w tle w IDE (JetBrains jest jawnie
  w zakresie wg `zalozenia.md`) — było nadpisywane nieaktualnym buforem, razem z przygotowanymi zmianami
  i bez żadnego komunikatu. Protokół gita jest odwrotny właśnie z tego powodu.
- **Naprawa**: `Lock` jako strażnik RAII zdejmowany na `Drop`; blokada jest brana **przed** odczytem,
  a każdy wcześniejszy `return` zwalnia ją.
- **Decyzja**: NAPRAWIONE

### F4 — plik tymczasowy z odszyfrowanym sekretem opisany jako „nigdy sekret"

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/atomic.rs:49` (przed naprawą)
- **Szczegóły**: komentarz modułu twierdził „to tekst atrybutów, nigdy sekret". Było to prawdą, gdy moduł
  powstawał w S-02, i przestało być prawdą w `8d1d461`: `unlock` przepisuje przez tę samą funkcję pliki
  drzewa roboczego, więc `SIGKILL` w trakcie zostawia **odszyfrowany sekret** pod nazwą
  `<plik>.git-xcrypt-<...>.tmp` — którą wzorzec `secrets/` jeszcze obejmuje, ale `*.env` już **nie**.
  Późniejsze `git add -A` mogłoby go zacommitować jawnie. Nieaktualne zdanie w dokumentacji było powodem,
  dla którego to ryzyko było niewidoczne w miejscu wywołania.
- **Naprawa**: dokumentacja mówi teraz wprost, że resztka może zawierać sekret i pod jaką nazwą; plik
  dziedziczy uprawnienia celu, więc nie jest szerzej czytelny niż plik, który zastępuje. Sprzątanie po
  `SIGKILL` nie ma przenośnej implementacji i nie jest udawane.
- **Decyzja**: NAPRAWIONE (dokumentacja); resztka po `SIGKILL` — ZAAKCEPTOWANA i zapisana

### F5 — „niewłaściwy klucz nie rusza niczego" nie obowiązywało przy pustym drzewie

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/unlock.rs:82` (przed naprawą)
- **Szczegóły**: `refuse_foreign_keys` może zaprotestować tylko przeciw kluczowi, przeciw któremu ma dowód.
  Gdy `collect_encrypted` zwraca pustkę — gałąź bez wypisanych sekretów, repozytorium świeżo zainicjowane,
  sekrety wyłącznie w historii — **niewłaściwy** klucz był instalowany, filtr rejestrowany, i nic tego nie
  zgłaszało. Kolejne commity szłyby pod kluczem niepasującym do istniejących blobów, trwale rozdzielając
  historię na dwa klucze. Komentarz modułu twierdził, że to nie może się zdarzyć.
- **Naprawa**: ostrzeżenie nazywające `key_id` i odsyłające do `status`, plus doprecyzowany komentarz
  modułu. Dowód wymagałby skanu historii, czyli `S-06`.
- **Test**: `a_key_nothing_can_vouch_for_is_taken_but_said_out_loud`.
- **Decyzja**: NAPRAWIONE

### F6 — jeden nieczytelny katalog przerywał całe `unlock`

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/unlock.rs:182-200` (przed naprawą)
- **Szczegóły**: `read_dir?`, `entry?`, `symlink_metadata?` i `peek_header?` propagowały wszystko. Jeden
  artefakt budowania należący do root-a, jeden katalog bez bitu `x`, jeden plik otwarty na wyłączność przez
  inny proces na Windows — i `unlock` kończył się `i/o failure: …` z kodem `1`, nie nazywając ścieżki i nie
  dając użytkownikowi drogi naprzód.
- **Naprawa**: błędy odczytu pojedynczych ścieżek trafiają do `Report.warnings` i praca idzie dalej; pominięcie
  pliku zawsze znaczy tylko „zostaje zaszyfrowany". Twardy błąd zostaje dla pliku, który **jest** nasz,
  a którego nagłówek nie daje się przeczytać.
- **Test**: `one_unreadable_directory_does_not_stop_the_whole_unlock`.
- **Decyzja**: NAPRAWIONE

### F7 — `BASE64.encode` zostawiał niewyzerowaną kopię klucza na stercie

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/keyfile.rs:139` (przed naprawą)
- **Szczegóły**: `text.push_str(&BASE64.encode(key.expose_bytes()))` — `encode` alokuje własny `String`
  z całym kluczem, `push_str` kopiuje z niego, a tymczasowy bufor ginie bez zerowania. Zewnętrzny `String`
  był poprawnie `Zeroizing` i poprawnie preallokowany, więc ochrona obejmowała jedną kopię z dwóch.
- **Naprawa**: `Zeroizing` również na wyniku `encode`.
- **Decyzja**: NAPRAWIONE

## Obserwacje

### F8 — przejście po wpisach indeksu nie miało walidacji końcowej

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/gitindex.rs:236` (przed naprawą)
- **Szczegóły**: po `count` wpisach kursor nie był porównywany z miejscem, w którym powinna zaczynać się
  sekcja rozszerzeń. Indeks o poprawnej sumie kontrolnej, ale niepoprawnej strukturze, mógł dać offsety,
  które nie są polami `size` — a przeliczona suma kontrolna uwiarygodniłaby szkodę wobec gita. Fuzzing
  recenzenta (12 000 mutacji z każdorazowym przeliczeniem sumy, wersje 2/3/4) **nie znalazł ani paniki,
  ani zapisu pod złym offsetem** — strażnicy `body[end] != 0` i `cursor > body.len()` odrzucają praktycznie
  wszystko — więc była to obrona w głąb, nie żywy błąd.
- **Naprawa**: przejście po rozszerzeniach z F2 musi skonsumować plik co do ostatniego bajtu, co jednocześnie
  dowodzi, że przejście po wpisach skończyło się tam, gdzie powinno.
- **Decyzja**: NAPRAWIONE

### F9 — zerowa suma kontrolna czytana jako `index.skipHash` bez sprawdzenia ustawienia

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/gitindex.rs:90`
- **Szczegóły**: `skip_hash` jest wnioskowane wyłącznie z tego, że ogon pliku jest zerowy. Indeks, któremu
  ogon wyzerował przerwany zapis, byłby więc łatany bez żadnej kontroli spójności.
- **Decyzja**: ZAAKCEPTOWANE — po naprawie F8 taki plik i tak nie przejdzie walidacji strukturalnej
  (przejście po wpisach i rozszerzeniach musi trafić dokładnie w koniec danych). Powód zapisany
  w komentarzu przy `skip_hash`.

### F10 — `.git-xcrypt` wczytywany po zainstalowaniu klucza

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/commands/unlock.rs:89` (przed naprawą)
- **Szczegóły**: literówka w `.git-xcrypt` przerywała `unlock` **po** zapisaniu klucza i edycji
  `.git/config`. W połączeniu z F5 znaczyło to, że niewłaściwy klucz mógł zostać po błędzie, który nie miał
  z kluczem nic wspólnego.
- **Naprawa**: konfiguracja jest wczytywana przed instalacją klucza. (`init` robi odwrotnie i ma to
  udokumentowane; tam naprawa i tak ma wylądować.)
- **Decyzja**: NAPRAWIONE

### F11 — `fill` nie ponawiał przy `Interrupted`

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/commands/unlock.rs:231`
- **Szczegóły**: sygnał w trakcie 38-bajtowego odczytu zamieniał się w twardy `Error::Io`. `std` ponawia
  `Interrupted` we własnych czytnikach.
- **Naprawa**: pętla ponawia.
- **Decyzja**: NAPRAWIONE

### F12 — katalogi tworzone przez `export-key` miały domyślne uprawnienia

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/commands/export_key.rs:48`
- **Szczegóły**: `create_dir_all` daje `0777 & ~umask`, zwykle `0755`. Sam klucz jest `0600`, więc materiał
  był bezpieczny, ale `export-key ~/keys/repo.key` tworzył `~/keys` czytelne dla wszystkich — katalog
  powstający wyłącznie po to, żeby trzymać klucze.
- **Naprawa**: `DirBuilder::mode(0o700)` na Uniksie; istniejące katalogi nietknięte.
- **Decyzja**: NAPRAWIONE

### F13 — `unlock` odszyfrowuje też pliki nieśledzone i bootstrapowe

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/commands/unlock.rs:104`
- **Szczegóły**: pętla jest sterowana wyłącznie nagłówkiem, świadomie, ale to znaczy również, że zaszyfrowana
  kopia zapasowa trzymana przez użytkownika w katalogu repozytorium zostaje zamieniona na jawną, a wykluczenia
  bootstrapowe nie są na tej ścieżce sprawdzane.
- **Naprawa**: zapisane w komentarzu modułu jako decyzja, nie efekt uboczny — plik z naszym magic jest nasz
  niezależnie od nazwy, a zostawienie go jako ciphertext byłoby zaskoczeniem.
- **Decyzja**: ZAAKCEPTOWANE (udokumentowane)

### F14 — dowiązania twarde i pliki tylko do odczytu

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/atomic.rs:45`
- **Szczegóły**: `rename` na miejsce zrywa dowiązanie twarde, a na Windows zapis na plik tylko do odczytu
  zawodzi, więc `unlock` nie odszyfruje takiego pliku.
- **Naprawa**: dopisane do listy ograniczeń w dokumentacji modułu.
- **Decyzja**: ZAAKCEPTOWANE (udokumentowane)

## Rozjazdy planu wobec stanu kodu

Odnotowane, nie naprawiane w kodzie:

- **`unlock` wybiera pliki po nagłówku, nie po wzorcach z `.git-xcrypt`.** Plan mówi „przechodzi po plikach
  drzewa roboczego objętych wzorcami". `zalozenia.md` §Integracja z git rozstrzyga jednak, że ścieżka smudge
  decyduje po nagłówku i nie czyta `.git-xcrypt` — wybieranie po wzorcach uczyniłoby `unlock` jedyną ścieżką
  deszyfrowania w produkcie z inną regułą selekcji, a to właśnie zgodność z checkoutem jest tym, czego
  dowodzi czysty `git status`. `.git-xcrypt` jest nadal czytany, ale wyłącznie po atrybut `eol=`.
- **`src/gitindex.rs` nie było w planie.** Kryterium 2.2 („`git status` po `unlock` czysty") okazało się
  wymagać własnego, pisanego ręcznie łatacza binarnego formatu indeksu gita. Powód jest zmierzony i zapisany
  w nagłówku modułu: git przy różnicy rozmiaru uznaje plik za zmieniony **bez** uruchomienia filtra, a klon
  wypisany bez klucza ma w indeksie rozmiar ciphertextu. To nie jest rozrost zakresu w intencji — bez tego
  własne kryterium planu nie przechodzi — ale jest to podsystem, którego plan nie przewidział, i najbardziej
  ryzykowny kod w tej zmianie.
- **`import-key` też rejestruje sterownik**, choć plan dał to zadanie wyłącznie `unlock`. Klucz bez
  rejestracji to stan, w którym następne `git add` zapisuje plaintext z kodem `0`; powód zapisany
  w komentarzu modułu.
- **`atomic::write_owner_only`, `repo::lexically_normal` upublicznione, `gix-hash`** — konsekwencje powyższych,
  każda uzasadniona we własnej dokumentacji. `gix-hash` był już w drzewie zależności, więc nie doszedł
  ani jeden nowy crate.
- **Rozjazd kodów wyjścia**: plan mówi „niezgodny `key_id` → kod `4`". To obowiązuje w scenariuszu planu
  (świeży klon bez klucza). W repozytorium, które **już** ma klucz, pierwszy protestuje `refuse_on_conflict`
  i kod wynosi `2`. Oba odmawiają i oba niczego nie zmieniają; różnica jest teraz opisana w `# Errors`
  przy `unlock::run`.

## Luki w weryfikacji, które zostają

- **Ścieżki spoza UTF-8 i `core.autocrlf=true` na Windows** — jak w S-01, wymagają nogi CI.
- **Resztka po `SIGKILL`** (F4) nie ma przenośnego sprzątania; ryzyko jest zapisane, nie usunięte.
- **`gitindex` przetestowany przeciw prawdziwemu gitowi 2.55 dla wersji 2, 3 i 4 oraz podzielonego indeksu**;
  repozytoria SHA-256 nie zostały przetestowane empirycznie — kod wybiera długość skrótu z
  `extensions.objectformat`, a suma kontrolna weryfikuje ten wybór, więc błąd kończy się `Skipped`.

## Drugi przebieg — to, czego pierwszy nie dotknął

Metoda: pełna weryfikacja każdej naprawy z `5043e58` przeciw prawdziwemu gitowi 2.55 (12 000 zmutowanych
indeksów, wszystkie 12 wyjść z `forget_stat`, rozszerzenia TREE / UNTR / REUC / EOIE / IEOT / brak,
indeks SHA-256, wersje 2/3/4, ścieżka 4615-bajtowa, podłączony worktree) plus osobny przebieg na
zachowaniu end-to-end, którego pierwszy przegląd w ogóle nie badał.

### G1 — `unlock` naprawiał `.git/config`, ale nie linię catch-all w `.gitattributes`

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/commands/unlock.rs:103`, `src/commands/import_key.rs:47` (przed naprawą)
- **Szczegóły**: `init` **tworzy** `.gitattributes`, ale go **nie commituje**. Użytkownik, który zrobi
  `git add .git-xcrypt secrets/ && git commit`, wypuszcza repozytorium, którego klony nie mają linii
  `* filter=git-xcrypt` w ogóle. `unlock` rejestrował sterownik w `.git/config` i na tym kończył —
  a git traktuje brakujący atrybut dokładnie tak samo jak niezdefiniowany sterownik: jako brak filtra.
  Komentarz modułu zakładał przesłankę, której nigdy nie sprawdzał („klon ma `* filter=git-xcrypt`
  w `.gitattributes` i nic za nim").

  Zmierzone na git 2.55, w klonie po `unlock`:

  ```
  $ git-xcrypt unlock ../k.key      # kod 0, „1 file(s) are now in the clear"
  $ printf 'new-secret-value\n' > secrets/db.env && git add -A && git commit -qm leak
  $ git cat-file -p HEAD:secrets/db.env
  new-secret-value
  ```

  To jest dokładnie tryb awarii zapisany w `zalozenia.md` §Konstrukcja catch-all — „filtr nieuruchomiony,
  `git add` i `commit` z kodem 0, plaintext w bazie obiektów, zero sygnału dla użytkownika" — a `unlock`
  jest tym, co wkłada ten plaintext do drzewa roboczego. Żaden istniejący test tego nie pokrywał:
  `commit_all` w harnessie zawsze commituje `.gitattributes`.
- **Naprawa**: `unlock` i `import-key` renderują sekcję zarządzaną tym samym kodem co `init`, przed
  deszyfrowaniem; wynik idzie przez `Report.attributes_written` do komunikatu.
- **Test**: `tests/key_transfer.rs::a_clone_whose_origin_never_committed_gitattributes_still_gets_the_catch_all`
  (fixture wyklucza `.gitattributes` przez `.git/info/exclude`; sprawdzony jako czerwony przed naprawą).
- **Decyzja**: NAPRAWIONE

### G2 — przejście po drzewie wchodziło w podmoduły, wbrew własnemu komentarzowi

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/commands/unlock.rs:220` (przed naprawą)
- **Szczegóły**: komentarz mówił „`.git` jest pomijany na każdym poziomie, co pomija również podmoduły".
  Pominięcie **wpisu** `.git` nie pomija **drzewa roboczego** podmodułu — przejście wchodziło do `sub/`
  i czytało każdy plik. Podmoduł z własnym kluczem blokował więc rodzica całkowicie:

  ```
  $ git-xcrypt unlock
  git-xcrypt: format error: sub/sub.env was encrypted with key 68dd088e…,
    but the key offered here is b87db899…. Nothing has been changed.   # kod 4
  ```

  Własne sekrety rodzica nie były odszyfrowane i nie było flagi, żeby przejść dalej; odblokowanie
  podmodułu najpierw kończy się kodem `3`, bo klon podmodułu nie ma własnego klucza. Druga konsekwencja
  w przypadku tego samego klucza: `unlock` przepisywał pliki w cudzym repozytorium, a łatał wyłącznie
  `repo.git_dir()/index` nazwami względem rodzica, więc indeks podmodułu w `.git/modules/sub/index`
  zostawał z nieaktualnym cache'em stat i bez ostrzeżenia.
- **Naprawa**: katalog zawierający wpis `.git` jest granicą repozytorium i nie jest odwiedzany;
  ostrzeżenie nazywa go i odsyła do jego własnego `unlock`. Komentarz poprawiony.
- **Test**: `src/commands/unlock.rs::a_nested_repository_is_left_to_its_own_unlock` (sprawdzony jako
  czerwony przed naprawą).
- **Decyzja**: NAPRAWIONE

### H1 — naprawa F6 poszerzyła zasięg: nieczytelny **plik** też był pomijany, przy kodzie wyjścia 0

- **Ważność**: ⚠️ OSTRZEŻENIE (poszerzenie naprawy z pierwszego przebiegu) · **Lokalizacja**: `src/commands/unlock.rs:266`
- **Szczegóły**: F6 miało naprawić „jeden nieczytelny katalog przerywał całe `unlock`". Kod był szerszy:
  `peek_header` zwraca `Error::Io` również gdy nie da się otworzyć **pliku**, i to też stawało się samym
  ostrzeżeniem. Zmierzone: przy `secrets/b.env` w trybie `0000` `unlock` kończy się kodem 0, plik zostaje
  ciphertextem, a linia podsumowania mówi „1 file(s) are now in the clear" — nie do odróżnienia od pełnego
  sukcesu. Osłabia to też pre-flight: plik z obcym `key_id`, którego nie da się otworzyć, nigdy nie dociera
  do `refuse_foreign_keys`.
- **Naprawa**: `Report.unreadable` jako osobna lista, a linia podsumowania mówi
  „N file(s) are now in the clear, M could not be read and may still be encrypted". Pomijanie zostaje —
  jeden artefakt należący do root-a nie może stać między użytkownikiem a jego sekretami — ale przestaje
  wyglądać jak komplet.
- **Test**: `a_file_that_could_not_be_read_is_counted_not_just_mentioned`.
- **Decyzja**: NAPRAWIONE

### H2 — `unlock` ignorował `Config::missing` i zostawiał repozytorium, w którym każde `git add` przerywa

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/unlock.rs:90`
- **Szczegóły**: przy nieobecnym `.git-xcrypt` `unlock` odszyfrowywał wszystko i kończył zerem, podczas gdy
  `decide::clean` traktuje ten sam stan jako fatalny. Zmierzone: `git status` po takim `unlock` daje
  `fatal: secrets/a.env: clean filter 'git-xcrypt' failed` i kod 128. Fail closed, więc bez wycieku, ale
  komenda raportowała pełny sukces, kładąc sekrety jawnie w drzewie, w którym żadne polecenie gita nie działa.
- **Naprawa**: ostrzeżenie nazywające plik i `git-xcrypt init`.
- **Decyzja**: NAPRAWIONE

### Obserwacje z drugiego przebiegu, naprawione

- Wyczerpana pętla ponowień w `atomic::create_temporary` zgłaszała `File exists (os error 17)` bez nazwy
  pliku — czytane jako „cel jest zajęty", czyli odwrotnie niż to, co się stało. Gałąź `unwrap_or_else` była
  martwa. Teraz jeden uczciwy komunikat z nazwą pliku (`src/atomic.rs:186`).
- „Rodzic jest plikiem" w `export-key` wychodziło jako gołe `File exists (os error 17)` bez ścieżki
  (`src/commands/export_key.rs:106`).
- `Zeroizing` w `encode_portable` działało wyłącznie dzięki temu, że `String::with_capacity(96)` przypadkiem
  starczało; realokacja zostawiłaby kopię klucza na stercie. Pojemność liczona ze stałych plus `debug_assert!`
  (`src/keyfile.rs:132`).
- Losowa nazwa pliku tymczasowego znaczy, że każdy zabity `unlock` zostawia **inną** resztkę zamiast jednej
  na PID; dokumentacja podaje teraz wzorzec `*.git-xcrypt-*.tmp` do sprzątania (`src/atomic.rs:63`).
- `Lock::commit` nie robił `sync_directory` po `rename`, w odróżnieniu od `atomic::replace`. Dodane
  (`src/gitindex.rs:396`).

### Potwierdzone jako poprawne w drugim przebiegu

Każda naprawa z `5043e58` prześledzona osobno, w większości empirycznie:

- **Blokada indeksu zwalniana na wszystkich 12 wyjściach** z `forget_stat`, w tym po 12 000 zmutowanych
  indeksach — `.git/index.lock` nigdy nie przeżył, a `git add` po każdym z nich działał. To był
  najgroźniejszy kształt regresji (osierocony lock wiesza każde późniejsze polecenie gita) i nie wystąpił.
- **Przejście po rozszerzeniach zgodne z prawdziwym gitem** na TREE, UNTR, REUC, EOIE+IEOT, indeksie bez
  rozszerzeń, indeksie z niezakończonym konfliktem, wpisie gitlink, `index.skipHash`, repozytorium SHA-256,
  wersjach 2/3/4, ścieżce 4615-bajtowej i ścieżkach spoza ASCII. `scan()` nie panikuje na żadnej z 12 000 mutacji.
- **`Mode::InheritTarget` niezmieniony przez `O_EXCL`**: świeży `.gitattributes` wychodzi `0644`, zawężony
  `.git/config` zostaje `0600`, skrypt `0755` zostaje `0755`.
- **`cfg(not(unix))` kompiluje się na Windows** — `cargo clippy --target x86_64-pc-windows-msvc --lib` czysty.
- **Determinizm i round-trip** (PRD Kryterium Akceptacji 6) na macierzy `core.autocrlf` ∈ {false, true, input}
  × {tekst CRLF, tekst LF, pusty plik, 2560 B binarny, 5 MB losowy}: każdy plik bajt w bajt, `git status` czysty,
  każdy ponownie dodany blob o identycznym oid. Bity wykonywalności zachowane.
- **Parzystość EOL filtra i `unlock`** — `serve` i `unlock::run` podają to samo `decision.encrypt` / `decision.eol`
  z tego samego `Config::decide`; checkout i unlock dają identyczne bajty również przy `text eol=crlf`.
- **Kody wyjścia** wszystkich nowych ścieżek zgodne z zamrożoną tabelą, sprawdzone przez uruchomienie binarki.
- **Komunikaty** — każdy nowy `eprintln!` przejrzany; wychodzi wyłącznie `format_key_id`, `stdout` pusty
  na każdej ścieżce łącznie z `--help`.

## Ustalenia świadomie odrzucone

- **Resztka po `SIGKILL`** w `atomic` — nie ma przenośnego sprzątania; ryzyko zapisane w dokumentacji modułu
  wraz ze wzorcem do wyszukania, nie usunięte.
- **`unlock` odszyfrowuje pliki nieśledzone i ignoruje wykluczenia bootstrapowe** (F13) — świadome, plik
  z naszym magic jest nasz niezależnie od nazwy.
- **Nieczytelny plik nadal nie przerywa `unlock`** (H1) — pomijanie zostaje, bo odzyskanie sekretów waży
  więcej niż kompletność; zmienia się tylko to, że wynik przestaje udawać komplet.
