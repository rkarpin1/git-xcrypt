<!-- IMPL-REVIEW-REPORT -->
# Przegląd implementacji: Przezroczyste szyfrowanie w jednym repozytorium

- **Plan**: `context/changes/transparent-encrypt-decrypt/plan.md`
- **Zakres**: Fazy 1–4 z 4 (wszystkie ukończone)
- **Data**: 2026-08-04
- **Werdykt**: ODRZUCONY po pierwszym przebiegu → ODRZUCONY po drugim → ZAAKCEPTOWANY
- **Ustalenia**: przebieg 1 — 4 krytyczne, 9 ostrzeżeń, 8 obserwacji;
  przebieg 2 — 1 krytyczne, 4 ostrzeżenia, 6 obserwacji
- **Przebiegi**: dwa. Drugi nie był formalnością: znalazł błąd **wprowadzony przez
  naprawę z pierwszego** (F14) i brak wektorów, który pozwolił mu przejść niezauważenie.

## Werdykty

| Wymiar | Przed naprawą | Po naprawie |
|---|---|---|
| Zgodność z planem | FAIL | PASS |
| Dyscyplina zakresu | WARNING | PASS |
| Bezpieczeństwo i jakość | FAIL | PASS |
| Architektura | PASS | PASS |
| Spójność wzorców | PASS | PASS |
| Kryteria sukcesu | PASS | PASS |

Bramka jakości po naprawach: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
i `cargo test` (130 testów) przechodzą.

## Ustalenia krytyczne — cztery drogi do jawnego sekretu w bazie obiektów

Wspólna cecha: `git add` kończył się kodem `0`, plaintext lądował w bazie obiektów,
użytkownik nie dostawał żadnego sygnału. To jest dokładnie tryb awarii, przed którym
broni cała konstrukcja catch-all i `required = true`.

### F1 — `trim_end()` na ścieżce zmieniał nazwę pliku

- **Ważność**: ❌ KRYTYCZNE · **Lokalizacja**: `src/filter.rs:131` (przed naprawą)
- **Szczegóły**: protokół przysyła `pathname=<nazwa>\n`; `trim_end()` obcinał **każdy**
  biały znak, nie tylko ten jeden `\n`. Plik `secrets/README.md ` (spacja na końcu, nazwa
  legalna na wszystkich trzech platformach) trafiał pod nazwę `secrets/README.md`, czyli
  wprost na negację, której **nie** dopasowuje. Zweryfikowane na prawdziwym repozytorium:
  blob jawny, kod wyjścia `0`.
- **Naprawa**: obcinany jest dokładnie jeden kończący `\n` (`strip_suffix(b"\n")`).
- **Test**: `tests/filter_edge_cases.rs::a_file_whose_name_ends_in_a_space_is_still_encrypted`.
- **Decyzja**: NAPRAWIONE

### F2 — ścieżka dekodowana stratnie przez `from_utf8_lossy`

- **Ważność**: ❌ KRYTYCZNE · **Lokalizacja**: `src/filter.rs:125` (przed naprawą)
- **Szczegóły**: `src/pktline.rs:5` sam zapisuje regułę — „ładunki to dowolne bajty, więc
  nic tutaj nie może stać się `String`" — a `filter.rs` łamał ją dla jedynego ładunku,
  który steruje decyzją szyfrować/przepuścić. Na Linuksie ścieżka to dowolny ciąg bajtów;
  każdy niepoprawny bajt stawał się U+FFFD **przed** dopasowaniem wzorca, więc plik był
  oceniany pod nazwą, której nie ma.
- **Naprawa**: ścieżka jest `Vec<u8>` od ładunku pkt-line aż do `Config::decide`;
  `gix-glob` i tak dopasowuje na `&BStr`, więc przejście przez `String` niczego nie dawało.
- **Ograniczenie weryfikacji**: nie do odtworzenia na macOS — APFS wymusza UTF-8.
  Empiryczny dowód wymaga nogi CI na Linuksie.
- **Decyzja**: NAPRAWIONE

### F3 — brak `.git-xcrypt` znaczył „nie szyfruj niczego"

- **Ważność**: ❌ KRYTYCZNE · **Lokalizacja**: `src/config.rs:162`, `src/filter.rs:42`
- **Szczegóły**: `zalozenia.md` §Integracja z git mówi wprost: *„Brak lub nieczytelny
  `.git-xcrypt` na ścieżce clean → błąd i przerwanie operacji, nigdy przepuszczenie
  treści."* `Config::load` mapował `NotFound` na pustą konfigurację. Komentarz doc nad tą
  funkcją twierdził dokładnie odwrotnie niż robił kod. Zweryfikowane: `init`, `rm
  .git-xcrypt`, `git add a.env` → kod `0` i sekret jawny w bazie obiektów. Jedno polecenie.
- **Naprawa**: nieobecność jest zapamiętywana w `Config::missing` i odmawiana **tylko na
  ścieżce check-in** — smudge musi działać dalej, bo plik jest samoopisujący, a git nie
  gwarantuje kolejności zapisu przy checkoucie. Dwie ostrożności wokół:
  - pliki bootstrapowe (`is_never_encrypted`) przechodzą **przed** odmową, żeby dało się
    naprawić stan;
  - `Context::refresh_config_if_absent()` szuka pliku ponownie, bo jeden proces obsługuje
    całą operację gita i `git checkout -- .git-xcrypt` filtruje inne pliki w tym samym
    przebiegu. Bez tego odmowa przeżywała własną przyczynę i repozytorium nie dawało się
    odblokować od środka.
- **Testy**: `deleting_the_declaration_stops_the_commit_instead_of_leaking`,
  `the_declaration_can_still_be_restored_after_it_is_deleted`.
- **Decyzja**: NAPRAWIONE

### F4 — `already_encrypted` nie sprawdzał tagu

- **Ważność**: ❌ KRYTYCZNE · **Lokalizacja**: `src/decide.rs:95` (przed naprawą)
- **Szczegóły**: zamrożona tabela idempotencji ma wiersz *„clean | magic + obcy `key_id`
  **albo zły tag** | błąd"*, a kontrakt Fazy 3 w planie mówi „`key_id` się zgadza **i tag
  przechodzi**". Kod porównywał sam `key_id` — pole leżące w nagłówku, gdzie każdy może je
  wpisać. Zweryfikowane: przekłamanie jednego bajtu ciphertextu → `git add` kod `0`,
  commit przechodzi, awaria wychodzi dopiero przy checkoucie, a uszkodzona treść zostaje
  w bazie obiektów na zawsze.
- **Naprawa**: `crypto::decrypt(key, content)?` przed przepuszczeniem; plaintext jest
  natychmiast porzucany, liczy się sam werdykt.
- **Test**: `src/decide.rs::tampered_ciphertext_is_refused_on_the_way_in`.
- **Decyzja**: NAPRAWIONE

## Ostrzeżenia

### F5 — `text=auto` rozjeżdżało się z gitem na samotnym `CR`

- **Ważność**: ⚠️ OSTRZEŻENIE (waga podniesiona przez moment) · **Lokalizacja**: `src/eol.rs:29`
- **Szczegóły**: git w `convert_is_binary` odmawia normalizacji, gdy treść zawiera `CR`
  bez `LF` (`stats->lonecr`); nasza heurystyka tego nie miała. Skutek nie był uszkodzeniem
  treści, tylko utratą determinizmu: `normalise_to_lf` nie jest domknięta na własnym
  wyjściu (`\r\r\n` → `\r\n` → `\n`), więc plik po checkoucie wracał inny i `git status`
  pokazywał zmianę, której nikt nie zrobił — czyli PRD §Guardrails i Kryterium Akceptacji 6.
  Waga wynika z terminu: reguła jest **zamrażana razem z formatem**, więc po wydaniu S-01
  jej zmiana wymagałaby nowego `suite`.
- **Naprawa**: `looks_binary` zwraca `true` dla samotnego `CR`, tak jak git.
- **Zamrożone wektory nietknięte** — `tests/format_vectors.rs` woła `crypto::encrypt`
  bezpośrednio, więc nie przechodzi przez tę regułę. Zweryfikowane empirycznie: `a\r\r\nb\r\n`
  i `old\rmac\r` wracają po checkoucie bajt w bajt, `git status` czysty.
- **Decyzja**: NAPRAWIONE

### F6 — czytana była tylko lokalna konfiguracja gita

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/filter.rs:53`
- **Szczegóły**: `open_local` czyta wyłącznie `.git/config`, a `core.autocrlf` jest
  ustawiany globalnie na praktycznie każdej maszynie, która ustawia go w ogóle — na Windows
  robi to instalator. Zmierzona tabela końców linii była więc martwa dokładnie na
  platformie, dla której istnieje. `zalozenia.md` wybrał `gix-config` *właśnie* za „pełną
  precedencję system/global/repo/worktree".
- **Naprawa**: nowa `gitconfig::open_full()` na `File::from_git_dir` (installation, system,
  global, local, worktree, `GIT_CONFIG_*`, z `include`/`includeIf`). Zapis nadal idzie
  przez `open_local` — `init` nie ma prawa dotykać cudzych plików.
- **Determinizm zachowany**: `autocrlf`/`core_eol` z `Context` są używane **wyłącznie** w
  gałęzi `smudge`. Zweryfikowane empirycznie: ten sam plik z CRLF przy
  `core.autocrlf` = `false`/`true`/`input` daje **identyczny blob** i czysty `git status`.
- **Decyzja**: NAPRAWIONE

### F7 — `init` rejestrował sterownik `diff`, którego nie ma

- **Ważność**: ⚠️ OSTRZEŻENIE · **Wymiar**: Dyscyplina zakresu · **Lokalizacja**: `src/commands/init.rs:130`
- **Szczegóły**: `diff.git-xcrypt.textconv = '<binarka>' diff`, przy czym `git-xcrypt diff`
  kończy się `error: unrecognized subcommand`. Plan wymienia w §„Czego NIE robimy" pozycję
  *„`diff` na treści odszyfrowanej — S-05"*. Uśpione tylko dlatego, że sekcja zarządzana nie
  emituje jeszcze linii `diff=git-xcrypt`; ożywa w momencie, w którym S-02 je doda.
- **Naprawa**: rejestracja usunięta do czasu S-05; `driver_keys()` ma dwa elementy, więc
  `status` z S-06 nie będzie raportował każdego repozytorium jako niekompletne.
- **Decyzja**: NAPRAWIONE

### F8 — HKDF zawodził otwarcie, oddając klucz z samych zer

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/key.rs:96`
- **Szczegóły**: `if hkdf.expand(...).is_err() { out.zeroize(); }` — gałąź nieosiągalna dla
  stałych długości, ale wybrany tryb awarii był najgorszy z możliwych: szyfrowanie ruszało
  dalej pod 64-bajtowym kluczem zerowym, a taki blob odszyfrowuje każdy. Wszystko inne w tym
  kodzie zawodzi zamknięcie (nieznany suite, zarezerwowany bit `flags`, nieznany atrybut).
- **Naprawa**: `assert!` na długości plus `expect` — przerwanie zamiast cichego klucza.
  Panika filtra przy `required = true` przerywa operację gita, więc jest bezpieczna.
- **Decyzja**: NAPRAWIONE

### F9 — `0600` obowiązywało tylko przy tworzeniu pliku klucza

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/keyfile.rs:89`
- **Szczegóły**: `OpenOptions::mode()` jest ignorowane, gdy plik już istnieje, więc plik z
  luźnymi uprawnieniami był obcinany, wypełniany kluczem i **zachowywał stary tryb** — wbrew
  temu, co twierdził jego własny komentarz. Dotyczy przede wszystkim `export-key` z S-03.
- **Naprawa**: uprawnienia są zawężane zaraz po otwarciu, przed pierwszym zapisem.
- **Test**: `a_pre_existing_loose_file_is_narrowed_before_the_key_lands_in_it`.
- **Decyzja**: NAPRAWIONE

### F10 — materiał klucza w buforach bez zerowania

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/keyfile.rs:23,44,71`, `src/key.rs:44`
- **Szczegóły**: `MasterKey` jest `ZeroizeOnDrop`, ale wokół niego leżały cztery kopie
  klucza, których nikt nie czyścił: bufor `encode`, bufor `fs::read`, tablica `material` w
  `decode` i tablica stagingowa w `generate`. Ochrona obejmowała jedną kopię z pięciu.
- **Naprawa**: `Zeroizing` na buforach sterty, `.zeroize()` na tablicach stosu.
- **Decyzja**: NAPRAWIONE

### F11 — `init` traktował nieczytelny `.gitattributes` jak brak śladów

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/init.rs:87`
- **Szczegóły**: `fs::read_to_string(...).unwrap_or_default()` zamieniał błąd odczytu na
  „brak sekcji zarządzanej". W połączeniu z nieobecnym `.git-xcrypt` ta ścieżka generuje
  **nowy klucz w repozytorium, które już ma sekcję zarządzaną** — czyli dokładnie ten
  nieodwracalny skutek, przed którym reguła druga istnieje.
- **Naprawa**: `NotFound` to nadal brak śladów; każdy inny błąd to odmowa z kodem `2`.
- **Decyzja**: NAPRAWIONE

### F12 — `.gitattributes` wykluczony tylko w korzeniu

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/config.rs:231`
- **Szczegóły**: git czyta `.gitattributes` w **każdym** katalogu; zaszyfrowany
  `sub/.gitattributes` byłby dla gita nieczytelny i całe poddrzewo traciłoby bootstrap.
  Zweryfikowane: przy wzorcu `*` ścieżka `sub/.gitattributes` była wybierana do szyfrowania.
- **Naprawa**: wykluczenie po basename. `.git-xcrypt` zostaje wykluczony tylko w korzeniu,
  bo tylko stamtąd jest czytany.
- **Decyzja**: NAPRAWIONE

### F13 — niekompletne żądanie kończyło proces kodem 0

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/filter.rs:141`
- **Szczegóły**: `command=clean` bez `pathname=` był nieodróżnialny od zamknięcia strumienia:
  proces kończył się zerem, nie odpowiedziawszy nic, a git widział filtr, który zakończył
  się pomyślnie.
- **Naprawa**: `Ok(None)` tylko gdy brakuje **obu** pól; cokolwiek częściowego to `Error::Format`.
- **Decyzja**: NAPRAWIONE

## Obserwacje naprawione przy okazji

- `core.autocrlf` honoruje teraz wszystkie git-owe zapisy prawdy (`1`, `yes`, `on`, klucz bez
  wartości), a nie tylko `true` — wcześniej cicho degradowały się do `false` (`src/eol.rs:113`).
- `unsafe_code = "forbid"` w `Cargo.toml` — twarda reguła z AGENTS.md była dotąd pilnowana
  wyłącznie umową.
- `BufWriter` wokół `stdout` na ścieżce filtra: `StdoutLock` jest liniowo buforowany, a
  ciphertext jest losowy, więc mniej więcej co 256. bajt to `\n` i wymuszał syscall — na
  ścieżce, której całym uzasadnieniem jest pomiar 22×. Zweryfikowane: plik 5 MB przechodzi
  round-trip bajt w bajt, bez zakleszczenia, `pktline::write_flush` nadal wymusza flush w
  każdym punkcie wymaganym przez protokół.
- `read_packet` wymaga czterech cyfr szesnastkowych; `from_str_radix` samo przyjmowało `+abc`.
- `Outcome` ma ręczny `Debug` wypisujący liczbę bajtów zamiast treści — wcześniej nieudany
  `assert!` wypisałby treść pliku do logu CI, wbrew regule „sekrety również w testach".
- Testy: kod wyjścia `2` jest teraz sprawdzany dosłownie (kryteria 2.3 i 2.4 asertowały samo
  `!success`), doszedł test `init` poza repozytorium git.

## Drugi przebieg — regresje i to, co umknęło

### F14 — `looks_binary` wciąż rozjeżdżał się z gitem, po naprawie F5

- **Ważność**: ❌ KRYTYCZNE · **Lokalizacja**: `src/eol.rs:29`
- **Szczegóły**: F5 dodało regułę samotnego `CR` i opisało funkcję jako zgodną z
  `convert_is_binary`. Zgodna nie była — zostały dwa rozjazdy, oba przesuwające
  realne pliki przez granicę tekst/binarny:
  - **`DEL` (`0x7f`)** liczony jako drukowalny; git liczy go do `nonprintable`
    mimo że jest powyżej `0x20`;
  - **`CR` i `LF`** liczone jako drukowalne; git robi na nich `continue` i nie
    liczy ich do żadnego kubełka, więc nasza lewa strona proporcji
    `(printable >> 7) < nonprintable` była zawyżona.

  Zmierzone na git 2.55, te same bajty do obu:

  | treść | git | git-xcrypt (przed) |
  | --- | --- | --- |
  | `\x7f` × 200 + `x\r\n` | binarny | **tekst** |
  | `\n` × 200 + `\x01\r\n` | binarny | **tekst** |

  Skutek: oba pliki commitowane po normalizacji, a po `rm` i `git checkout --`
  wracały o bajt krótsze — `CR` znikał na trwałe — przy czystym `git status`, więc
  użytkownik nie dostawał żadnego sygnału. Ciche uszkodzenie pliku, który git sam
  uznaje za binarny, wprost przeciw guardrailowi „filtr nigdy nie uszkadza pliku".
- **Naprawa**: `looks_binary` jest teraz portem `gather_stats` + `convert_is_binary`
  bajt w bajt. Zweryfikowane przeciw prawdziwemu gitowi na sześciu kształtach —
  werdykty zgodne we wszystkich sześciu, pliki binarne wracają identyczne.
- **Decyzja**: NAPRAWIONE

### F15 — reguła `text=auto` zamrożona bez wektorów

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `tests/format_vectors.rs`
- **Szczegóły**: `zalozenia.md` żąda dla tej reguły **własnych wektorów testowych**,
  obok wektorów formatu. Nie istniały. Cztery zamrożone wektory wołają
  `crypto::encrypt` z jawnymi flagami, więc są ślepe na `looks_binary` — i to jest
  dokładny powód, dla którego naprawa F5 mogła przesunąć granicę tekst/binarny,
  czyli wprowadzić zmianę niekompatybilną wstecz, przy zielonym całym zestawie.
  Bez tego F14 też przeszłoby niezauważone.
- **Naprawa**: zamrożona tabela werdyktów dla piętnastu kształtów treści plus wektor
  przechodzący przez `decide::clean`, a nie `crypto::encrypt` — pinuje cały łańcuch:
  dopasowanie wzorca, werdykt tekst/binarny, bit `flags`, ciphertext.
- **Decyzja**: NAPRAWIONE

### F16 — ostrzeżenie „stored in the clear" dla każdego pliku w repozytorium

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/decide.rs:164`
- **Szczegóły**: smudge ostrzegał zawsze, gdy treść nie ma magic, nie pytając, czy
  ścieżka jest w ogóle wybrana — a konstrukcja catch-all przepuszcza przez smudge
  **każdy** plik. Zmierzone: checkout repozytorium z 301 plikami dawał 301 ostrzeżeń,
  z czego **zero** dotyczyło ścieżki wybranej. Jedyny komunikat, który coś znaczy,
  tonął w reszcie, a świeży klon witał użytkownika ścianą „whether it leaked".
  Uzasadnienie tego ostrzeżenia w `zalozenia.md` jest wąskie: plik zacommitowany,
  zanim wzorzec trafił do konfiguracji — czyli ścieżka **wybrana**, znaleziona jawna.
- **Naprawa**: bramka na `Decision::encrypt`. To samo repozytorium: jedno ostrzeżenie.
- **Decyzja**: NAPRAWIONE

### F17 — bezwartościowy `core.autocrlf` czytany jako fałsz

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/gitconfig.rs:55`, `src/eol.rs:146`
- **Szczegóły**: `[core]` z samym `autocrlf` bez wartości jest dla gita prawdą
  (zweryfikowane). `get` to było `raw_value(key).ok()`, a gix-config nie ma surowej
  wartości dla klucza bez wartości, więc wychodziło `None` i tabela spadała do
  `core.eol` → `Native`. Gałąź `is_git_true("")` dodana przy F6 była martwym kodem.
- **Naprawa**: `get` odróżnia klucz nieobecny od obecnego bez wartości i zwraca dla
  tego drugiego `Some("")`. Samonaprawialne, więc determinizm był nienaruszony —
  ale katalog roboczy dostawał ciche złe końce linii.
- **Decyzja**: NAPRAWIONE

### F18 — `init` nie usuwał sterownika `diff` zapisanego przez starszy build

- **Ważność**: ⚠️ OSTRZEŻENIE · **Lokalizacja**: `src/commands/init.rs:119`
- **Szczegóły**: F7 przestało *pisać* `diff.git-xcrypt.textconv`, ale nie usuwało go
  tam, gdzie już jest. Zweryfikowane: przy obecnym kluczu `init` wypisywał „already
  set up; nothing to do" i zostawiał klucz w `.git/config`. Kto uruchomił poprzedni
  build, zachowywał dokładnie tę awarię, której naprawa miała zapobiec — a kontrakt
  `init` brzmi „naprawiamy resztę".
- **Naprawa**: `register_driver` kasuje klucze, których już nie chce; nowa
  `gitconfig::unset`.
- **Decyzja**: NAPRAWIONE

### Obserwacje z drugiego przebiegu, naprawione

- Wzorzec z końcową spacją (`!secrets/README.md\ `) był niezapisywalny: `raw.trim_end()`
  zjadał escape, zanim `split_pattern` — jedyna funkcja, która go rozumie — zdążyła go
  zobaczyć. To dokładne dopełnienie naprawy F1: filtr dopasowywał takie ścieżki
  poprawnie, ale deklaracja nie umiała ich nazwać (`src/config.rs:120`).
- Koniec strumienia w środku żądania był traktowany jak czyste zamknięcie, więc proces
  kończył się zerem, nie odpowiedziawszy nic. `read_content` traktował ten sam warunek
  jako błąd — dwie połówki się nie zgadzały (`src/filter.rs:173`).
- Plaintext z weryfikującego deszyfrowania zostawał na stercie; teraz `Zeroizing`
  (`src/decide.rs:140`).

### Potwierdzone jako poprawne w drugim przebiegu

Wszystkie trzynaście napraw z pierwszego przebiegu prześledzono osobno. Warte
odnotowania, bo to były realne ryzyka:

- **Determinizm nienaruszony przez `open_full`** — `autocrlf`/`core_eol` trafiają
  wyłącznie do `decide::smudge`; `clean` nie ma na nie parametru. Zweryfikowane
  macierzą 3 × 3 (`core.autocrlf` × `core.eol`): wszystkie dziewięć blobów identyczne.
- **Brak zakleszczenia po `BufWriter`** — każda granica protokołu przechodzi przez
  `write_flush`, które woła `flush()`. Zweryfikowane plikiem 64 MB i 4001 plikami.
- **`refresh_config_if_absent` bez wady** — zero kosztu na ścieżce gorącej, brak pętli
  ponowień, podmiana tylko gdy plik faktycznie wrócił.
- **Nowe testy testują to, co twierdzą** — sprawdzone przeciw staremu kodowi.

## Ustalenia świadomie odrzucone

- **`.git-xcrypt` jako ślad brany z katalogu roboczego, nie z HEAD** (`init.rs:89`).
  `zalozenia.md` mówi „w HEAD"; sprawdzenie tego bez odpalania gita wymagałoby `gix-odb`
  albo `gix-index`, a rozjazd myli tylko w kierunku fail-closed (świeże repozytorium z
  ręcznie napisanym `.git-xcrypt` dostaje odmowę). Zamiast poszerzać zależności, komunikat
  odmowy nazywa teraz ten trzeci przypadek i mówi, co zrobić.
- **Smudge czyta `.git-xcrypt` po atrybut `eol=`** — sprzeczne ze zdaniem „smudge nie czyta
  go w ogóle", ale wymagane przez sekcję §Końce linii tego samego dokumentu, która celowo
  trzyma `eol=` poza nagłówkiem i nazywa wybór samonaprawialnym. Niespójny jest dokument,
  nie kod.
- **Brak wektora RFC 5297 Appendix A.2** — A.2 opisuje SIV z wieloma nagłówkami AD, a my
  podajemy dokładnie jeden element. A.1 jest wektorem stosującym się do naszej konstrukcji.
- ~~**`0x7f` (DEL) liczony jako drukowalny**~~ — odrzucone w pierwszym przebiegu jako
  „nie powoduje uszkodzenia treści". **Błędna ocena**: drugi przebieg pokazał
  zmierzony przypadek, w którym powoduje. Patrz F14. Lekcja: „rozjazd z gitem bez
  widocznego skutku" trzeba było zweryfikować, a nie oszacować.
- **`gix-ignore` nieużyty** — dopasowanie stoi na `gix-glob` z jawnym przejściem po
  katalogach nadrzędnych. `gix-ignore` obsługuje stos plików ignore, którego tu nie ma;
  semantyka jest ta sama i pokryta testami.
- **Bezwzględna ścieżka binarki w `.git/config`** — przeniesienie binarki psuje każdą
  operację gita w repozytorium przy `required = true`. Realne, ale należy do `status`
  (S-06), który ma sprawdzać kompletność konfiguracji, plus do dokumentacji użytkownika.
- **`Error::Io` mapowane na kod `1`** — zamrożona tabela daje `1` znaczenie „błąd użycia
  **lub nieznany**", więc I/O się w nim mieści.
- **`subtle` na licencji BSD-3-Clause** — permisywna, bez ryzyka copyleft; wymaga jedynie
  wpisu w przyszłej konfiguracji `cargo deny`.
- **Zdolności protokołu ogłaszane bez przecięcia z ofertą gita** (`filter.rs:109`) — git
  ignoruje zdolności, których nie prosił; brak skutku obserwowalnego.

## Luki w weryfikacji, które zostają

- **Ścieżki spoza UTF-8** nie są testowalne na macOS (APFS wymusza UTF-8). Naprawa F2 jest
  poprawna z konstrukcji, ale dowód empiryczny wymaga nogi CI na Linuksie.
- **`core.autocrlf=true` na Windows** — `zalozenia.md` §Jakość i testy przewiduje scenariusz
  regresyjny; tabela jest dziś pokryta wyłącznie testami jednostkowymi `resolve_output`.
- **Kryterium 4.7** („jeden proces obsługuje wszystkie pliki") jest dowodzone testem
  jednostkowym protokołu; test integracyjny o tej nazwie sprawdza w rzeczywistości tylko to,
  że 25 plików zostało zaszyfrowanych.
