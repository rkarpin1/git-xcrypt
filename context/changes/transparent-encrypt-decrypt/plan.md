# Przezroczyste szyfrowanie w jednym repozytorium — plan implementacji

## Przegląd

Zamieniamy placeholder `__test-filter` (odwracanie bajtów) na kompletną ścieżkę
produkcyjną: AES-256-SIV, własny format pliku, klucz repozytorium, komendę `init`
oraz filtr gita w wariancie długożyjącym. Po tym elemencie `git add` na pliku
pasującym do wzorca daje w bazie obiektów ciphertext, `git checkout` daje
plaintext, a `git status` jest czysty.

## Analiza stanu obecnego

- `src/lib.rs:26` — `transform()` odwraca bajty; deterministyczne i samoodwrotne,
  ale to nie jest szyfrowanie. Do usunięcia.
- `src/lib.rs:35` — `run_filter()` buforuje całe wejście przed zapisem. Ten kształt
  zostaje: SIV wymaga dwóch przebiegów po danych.
- `src/main.rs:20` — jedyne komendy to `__test-filter` i `__test-filter --fail`.
  Do usunięcia w Fazie 4; AGENTS.md wymaga tego wprost.
- `tests/harness/mod.rs:68` — harness rejestruje `filter.<name>.clean/smudge`.
  Musi nauczyć się rejestrować `filter.<name>.process`.
- `tests/filter_edge_cases.rs:82,99` — dwa testy pilnują `required = true`.
  Muszą przetrwać przejście na nowy filtr bez zmiany sensu.
- `Cargo.toml` — jedyne zależności to `thiserror` i `tempfile` (dev).

## Pożądany stan końcowy

W nowym repozytorium: `git init`, `git-xcrypt init`, dopisanie wzorca do
`.git-xcrypt`, `git add` i `git commit` — blob w bazie obiektów zaczyna się od
`\x00GITXCRYPT\x00`, plik w katalogu roboczym jest jawny, `git status` po
checkoucie milczy. Klon bez klucza pokazuje ciphertext.

### Kluczowe odkrycia

- Format pliku i wszystkie decyzje kryptograficzne są **zamrożone** w
  `context/foundation/zalozenia.md` §Kryptografia i format pliku. Plan ich nie
  wymyśla, tylko realizuje.
- Konstrukcja catch-all (`* filter=git-xcrypt` w `.gitattributes`) oznacza, że
  filtr dostaje **każdy** plik repozytorium — patrz `zalozenia.md` §Integracja z
  git → „Konstrukcja catch-all".
- Filtr długożyjący jest warunkiem wykonalności, nie optymalizacją: zmierzone
  540 ms bez filtra, 12 105 ms z procesem na plik, 596 ms z długożyjącym.
- `required = true` jest jedynym powodem, dla którego błąd filtra przerywa
  operację gita.

## Czego NIE robimy

- `export-key`, `import-key`, `unlock`, `lock` — S-03 i S-04.
- Generowanie kosmetycznych linii `-text` / `diff` w `.gitattributes` i komenda
  `sync` — S-02.
- `diff` na treści odszyfrowanej — S-05.
- `status`, skan historii, `--fix` — S-06.
- Koperty odbiorców, rotacja klucza, wiele kluczy — poza v0.1.
- Buforowanie dyskowe dla wielkich plików — otwarta decyzja 5, świadomie odłożona.

## Podejście do implementacji

Cztery fazy, każda w pełni testowalna bez następnej. Kryptografia i format
najpierw, bo wszystko inne od nich zależy i bo to one są zamrażane na zawsze.
Potem klucz i `init`, potem konfiguracja i decyzje per plik, na końcu protokół
gita, który spina całość i usuwa placeholder.

## Krytyczne szczegóły implementacji

**Kolejność bajtów w AAD.** Nagłówek `0..22` idzie do AES-SIV jako associated
data **przed** zaszyfrowaniem, a przy deszyfrowaniu musi zostać odtworzony bajt w
bajt z odczytanego nagłówka. Zbudowanie AAD z wartości „oczekiwanych" zamiast z
faktycznie odczytanych bajtów ukryłoby manipulację polem `suite` lub `flags`.

**`stdout` na ścieżce filtra.** W wariancie długożyjącym cały protokół idzie
przez `stdout`, więc zakaz z AGENTS.md jest tu jeszcze ostrzejszy: żadnego
`println!` w całym drzewie wywołań filtra. Diagnostyka wyłącznie `eprintln!`.

**Kolejność przy normalizacji EOL.** Normalizacja `CRLF→LF` zachodzi na
plaintexcie **przed** szyfrowaniem i musi być idempotentna — `LF` już
znormalizowany nie może zmienić się ponownie. Samotny `CR` bez `LF` zostaje
nietknięty.

---

## Faza 1: Rdzeń kryptograficzny i format pliku

### Przegląd

Czysta biblioteka, zero wiedzy o gicie. Klucz główny, wyprowadzanie, nagłówek,
szyfrowanie i deszyfrowanie, wraz z zamrożonymi wektorami testowymi.

### Wymagane zmiany

#### 1. Zależności

**Plik**: `Cargo.toml`

**Cel**: wprowadzić kryptografię z RustCrypto i generator losowości.

**Kontrakt**: `aes-siv = "0.7"`, `hkdf = "0.13"`, `sha2 = "0.11"`,
`getrandom` (albo `rand_core` z `getrandom`), `thiserror` bez zmian. Bez
`rust-version` — MSRV zostaje płynny zgodnie z decyzją. Wszystkie licencje muszą
być `MIT OR Apache-2.0`.

#### 2. Klucz główny i wyprowadzanie

**Plik**: `src/key.rs`

**Cel**: reprezentacja klucza repozytorium i wyprowadzanie z niego materiału dla
suite oraz identyfikatora klucza.

**Kontrakt**: typ `MasterKey` opakowujący 32 bajty, generowany z CSPRNG.
`MasterKey::derive_suite_key(suite) -> [u8; 64]` przez HKDF-SHA-256 z
`info = "git-xcrypt suite 0x01 aes-256-siv"`. `MasterKey::key_id() -> [u8; 8]`
przez HKDF-SHA-256 z `info = "git-xcrypt key-id v1"`. Typ nie może implementować
`Debug`/`Display` wypisujących materiał klucza ani `Clone` bez potrzeby.

#### 3. Nagłówek formatu

**Plik**: `src/format.rs`

**Cel**: kodowanie i dekodowanie 22-bajtowego nagłówka wraz z regułą fail closed.

**Kontrakt**: stałe `MAGIC: [u8; 11] = *b"\x00GITXCRYPT\x00"`,
`FORMAT_VERSION: u8 = 1`, `SUITE_AES_256_SIV: u8 = 1`, `FLAG_LF_NORMALIZED: u8 = 0b0000_0001`,
`HEADER_LEN = 22`, `SIV_LEN = 16`, `OVERHEAD = 38`. Funkcja rozpoznająca
`starts_with(MAGIC)`. Dekoder odrzuca: nieznaną wersję, nieznany `suite`,
**każdy ustawiony bit poza bitem 0** w `flags`, wejście krótsze niż `OVERHEAD`.

#### 4. Szyfrowanie i deszyfrowanie

**Plik**: `src/crypto.rs`

**Cel**: jedna para funkcji, z której korzystają wszystkie ścieżki produktu.

**Kontrakt**: `encrypt(key: &MasterKey, flags: u8, plaintext: &[u8]) -> Vec<u8>`
buduje nagłówek, przekazuje go jako associated data do `Aes256Siv` i skleja
`nagłówek || siv || ciphertext`. `decrypt(key: &MasterKey, blob: &[u8]) -> Result<(u8, Vec<u8>)>`
zwraca flagi i plaintext, weryfikując tag; niepowodzenie to błąd. Używamy API
jednorazowego, **nigdy `*_detached`** — RUSTSEC-2023-0096.

#### 5. Wektory testowe

**Plik**: `tests/vectors/rfc5297.rs`, `tests/vectors/format.rs` (albo moduły w
`tests/format_vectors.rs`)

**Cel**: zamrozić zarówno zgodność z RFC 5297, jak i nasz własny format.

**Kontrakt**: wektory z RFC 5297 Appendix A sprawdzają, że crate liczy to, co mówi
specyfikacja. Wektory formatu to trójki (klucz, plaintext, oczekiwany blob w hex)
dla: pliku pustego, jednobajtowego, tekstowego, binarnego z pełnym zakresem bajtów.
Raz zapisane nie zmieniają się.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- Testy przechodzą: `cargo test`
- Clippy bez ostrzeżeń: `cargo clippy --all-targets -- -D warnings`
- Formatowanie: `cargo fmt --check`
- Wektory RFC 5297 Appendix A przechodzą
- `decrypt(encrypt(x)) == x` dla pustego, jednobajtowego, tekstowego i binarnego
- `encrypt(x) == encrypt(x)` — determinizm
- Zmiana dowolnego bajtu bloba powoduje błąd deszyfrowania
- Podmiana bajtu `suite`, `flags` lub `key_id` powoduje błąd, nie ciche przyjęcie
- Pusty plaintext daje dokładnie 38 bajtów

#### Weryfikacja ręczna

- Wektory formatu przejrzane pod kątem tego, że faktycznie zamrażają format, a nie
  powtarzają implementację

---

## Faza 2: Przechowywanie klucza i komenda `init`

### Przegląd

Plik klucza w `.git/git-xcrypt/keys/`, wykrywanie repozytorium bez procesu
potomnego, trzy reguły detekcji stanu, rejestracja filtra i sekcji catch-all.

### Wymagane zmiany

#### 1. Zależności

**Plik**: `Cargo.toml`

**Cel**: dostęp do repozytorium i konfiguracji bez uruchamiania `git`.

**Kontrakt**: `gix-discover`, `gix-config`, `clap` z `derive`. Pojedyncze crate'y
`gix-*`, nie cały `gix`.

#### 2. Plik klucza

**Plik**: `src/keyfile.rs`

**Cel**: zapis i odczyt klucza repozytorium z własnym nagłówkiem i wersją.

**Kontrakt**: format binarny z magic i bajtem wersji, potem 32 bajty klucza
głównego. Zapis ustawia `0600` na Uniksie; na Windows ogranicza ACL do właściciela
albo — jeśli to wykracza poza fazę — zostawia jawne `TODO` z testem oznaczonym
`#[cfg(unix)]`. Odczyt weryfikuje magic i wersję.

#### 3. Wykrywanie stanu repozytorium

**Plik**: `src/repo.rs`

**Cel**: ustalić, w jakim stanie jest repozytorium, bez uruchamiania `git`.

**Kontrakt**: `discover()` zwraca ścieżkę `.git` i korzeń drzewa roboczego przez
`gix-discover`; brak repozytorium → błąd z kodem `2`. `state()` raportuje cztery
niezależne elementy: obecność klucza, wpisy `filter.git-xcrypt.*` w konfiguracji,
plik `.git-xcrypt`, sekcja zarządzana w `.gitattributes`.

#### 4. Komenda `init`

**Plik**: `src/commands/init.rs`

**Cel**: zrealizować trzy reguły detekcji stanu z `zalozenia.md`.

**Kontrakt**: klucz istnieje → nie ruszamy go, naprawiamy resztę, raportujemy co
poprawiono, kod `0`. Klucza brak, ale są ślady konfiguracji (sekcja zarządzana w
`.gitattributes` albo `.git-xcrypt` w HEAD) → odmowa z kodem `2` i wskazaniem
`unlock` / `import-key`. Klucza brak i śladów brak → świeża inicjacja. Bez flagi
`--force`.

#### 5. Zapis konfiguracji

**Plik**: `src/commands/init.rs`

**Cel**: zarejestrować filtr i wpisać sekcję catch-all.

**Kontrakt**: `filter.git-xcrypt.process` wskazujące na bieżącą binarkę z
podkomendą `process`, `filter.git-xcrypt.required = true`. Sekcja w
`.gitattributes` ograniczona markerami `# >>> git-xcrypt >>>` /
`# <<< git-xcrypt <<<`, zawierająca **wyłącznie** `* filter=git-xcrypt`; ponowny
zapis jest idempotentny i nie rusza treści poza markerami.

#### 6. Kody wyjścia i szkielet CLI

**Plik**: `src/main.rs`, `src/exit.rs`

**Cel**: jeden zestaw kodów dla całego produktu.

**Kontrakt**: `0` sukces, `1` błąd użycia lub nieznany, `2` błąd konfiguracji lub
konfliktu stanu, `3` brak klucza, `4` błąd formatu, `5` znaleziono ekspozycję
(zarezerwowane dla S-06). Parsowanie przez `clap` z `derive`.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- `init` w świeżym repozytorium tworzy klucz, wpisy w `.git/config` i sekcję w `.gitattributes`
- Powtórny `init` **nie zmienia bajtów pliku klucza**
- `init` bez klucza, ale z sekcją zarządzaną w `.gitattributes` kończy się kodem `2`
- `init` poza repozytorium git kończy się kodem `2`
- Uprawnienia pliku klucza to `0600` (test `#[cfg(unix)]`)
- Sekcja w `.gitattributes` jest idempotentna i nie niszczy treści użytkownika
- `cargo clippy --all-targets -- -D warnings` przechodzi

#### Weryfikacja ręczna

- Komunikat `init` przy odmowie faktycznie kieruje użytkownika do właściwej komendy

---

## Faza 3: Konfiguracja `.git-xcrypt`, dopasowanie ścieżek i końce linii

### Przegląd

Parser pliku konfiguracyjnego wraz z pełnym słownikiem konwersji, dopasowanie
ścieżek semantyką `.gitignore` i decyzja per plik, z której korzysta filtr.

### Wymagane zmiany

#### 1. Zależności

**Plik**: `Cargo.toml`

**Kontrakt**: `gix-ignore`, `gix-glob`.

#### 2. Parser `.git-xcrypt`

**Plik**: `src/config.rs`

**Cel**: wczytać deklaracje użytkownika i rozstrzygać je na dwóch osiach.

**Kontrakt**: linia to wzorzec plus opcjonalne atrybuty oddzielone białymi znakami.
Atrybuty: `text`, `-text`, `binary`, `text=auto`, `eol=lf`, `eol=crlf`,
`eol=native`. Dwie niezależne osie: **selekcja** — ostatnie dopasowanie wygrywa,
`!` wyłącza; **atrybuty** — późniejsza linia nadpisuje tylko to, co wymienia, linia
bez atrybutów niczego nie zeruje, nic nieustawione → `text=auto`. Dwa niezależne
sloty: tryb tekstu i `eol`. Nieznany atrybut → błąd. Atrybuty na linii z negacją →
błąd. `eol=` przy `-text` → ostrzeżenie na `stderr`, bez przerwania.

#### 3. Twarde wykluczenia

**Plik**: `src/config.rs`

**Cel**: nie dopuścić do zaszyfrowania plików potrzebnych do bootstrapu.

**Kontrakt**: `.gitattributes`, `.git-xcrypt` i wszystko pod `.git-xcrypt-keys/`
nigdy nie są szyfrowane, niezależnie od wzorców i negacji.

#### 4. Heurystyka `text=auto`

**Plik**: `src/eol.rs`

**Cel**: odtworzyć regułę gita jako czystą funkcję treści.

**Kontrakt**: binarny, jeśli treść zawiera bajt `0x00` **albo** liczba znaków
sterujących poniżej `0x20` (z wyłączeniem `\t`, `\n`, `\r`, `\f`, `\b`, `0x1B`)
przekracza `printable >> 7`. Skan **całej** treści, nigdy zaglądanie do indeksu.
Reguła jest zamrożona wraz z formatem i ma własne wektory testowe.

#### 5. Konwersja końców linii

**Plik**: `src/eol.rs`

**Cel**: normalizacja przy clean i odtworzenie przy smudge.

**Kontrakt**: `normalize_to_lf(&[u8]) -> Vec<u8>` zamienia `CRLF` na `LF`,
zostawia samotny `CR`, jest idempotentna. `apply_eol(&[u8], mode) -> Vec<u8>`
odtwarza końcówkę na wyjściu smudge. Tryb wynika z `eol=` w `.git-xcrypt`, a przy
jego braku z konfiguracji gita czytanej przez `gix-config`: `autocrlf=true` → CRLF,
`autocrlf=input` → LF, `autocrlf=false` → według `core.eol`, `native` → platforma.

#### 6. Decyzja per plik

**Plik**: `src/decide.rs`

**Cel**: jedno miejsce, w którym zapada „szyfrować czy przepuścić".

**Kontrakt**: `clean(path, content)` — brak dopasowania lub wykluczenie →
przepuszczenie bez zmian; dopasowanie i treść już z naszym magic → przepuszczenie,
jeśli `key_id` się zgadza i tag przechodzi, inaczej błąd `4`; dopasowanie i
plaintext → normalizacja według atrybutów, ustawienie bitu `flags` i szyfrowanie.
`smudge(path, content)` — treść z naszym magic → deszyfrowanie i odtworzenie
końcówek; bez magic → przepuszczenie z ostrzeżeniem na `stderr`.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- **Test właściwości: `passthrough(x) == x`** dla losowych bajtów, w tym pustych,
  wielkich i binarnych — obowiązkowy, promień rażenia to całe repozytorium
- Wzorzec `sekrety/` obejmuje `sekrety/a/b.txt`
- Negacja `!sekrety/README.md` wyłącza plik z szyfrowania
- Szeroki wzorzec bez atrybutów nie kasuje deklaracji z linii wcześniejszej
- Nieznany atrybut i atrybut przy negacji kończą się błędem
- `.gitattributes`, `.git-xcrypt` i `.git-xcrypt-keys/` nigdy nie są szyfrowane
- Heurystyka `text=auto`: NUL → binarny, bajty sterujące → binarny, bajty `≥0x80` → tekst
- `normalize_to_lf` jest idempotentna i zostawia samotny `CR`
- Ponowne szyfrowanie ciphertextu z naszym `key_id` zwraca go bez zmian
- Ciphertext z obcym `key_id` na ścieżce clean daje błąd `4`

#### Weryfikacja ręczna

- Ostrzeżenie przy `eol=` na ścieżce `-text` jest zrozumiałe

---

## Faza 4: Filtr długożyjący i usunięcie placeholdera

### Przegląd

Protokół `filter.<driver>.process` (pkt-line), podpięcie decyzji z Fazy 3,
usunięcie `__test-filter` i przestrojenie harnessu na nowy sposób rejestracji.

### Wymagane zmiany

#### 1. Kodek pkt-line

**Plik**: `src/pktline.rs`

**Cel**: warstwa transportowa protokołu.

**Kontrakt**: pakiet to cztery cyfry szesnastkowe długości (wliczając te cztery
bajty) i ładunek; `0000` to flush. Funkcje odczytu i zapisu pakietu oraz odczytu
i zapisu strumienia zakończonego flushem. Ładunki mogą być binarne i mogą
przekraczać maksymalny rozmiar pakietu, więc zapis dzieli je na części.

#### 2. Pętla protokołu

**Plik**: `src/filter.rs`

**Cel**: obsłużyć uzgodnienie i kolejne żądania w jednym procesie.

**Kontrakt**: uzgodnienie — git przysyła `git-filter-client`, `version=2`, flush;
odpowiadamy `git-filter-server`, `version=2`, flush. Zdolności — git przysyła
`capability=clean`, `capability=smudge`, flush; odpowiadamy listą tych, które
obsługujemy. Żądanie — `command=`, `pathname=`, flush, treść, flush; odpowiedź —
`status=success`, flush, treść, flush, flush. Błąd pojedynczego pliku →
`status=error`, co przy `required = true` przerywa operację gita.

#### 3. Komenda `process`

**Plik**: `src/main.rs`, `src/commands/process.rs`

**Cel**: wejście, które rejestruje `init`.

**Kontrakt**: `git-xcrypt process` czyta protokół ze `stdin` i pisze na `stdout`.
Żadnego innego zapisu na `stdout` w całym drzewie wywołań.

#### 4. Usunięcie placeholdera

**Plik**: `src/lib.rs`, `src/main.rs`

**Cel**: wypełnić wymóg z AGENTS.md.

**Kontrakt**: `transform()`, `run_filter()`, `__test-filter` i `--fail` znikają.
Wydana binarka nie może wystawiać przekształcenia wyglądającego jak szyfrowanie.

#### 5. Przestrojenie harnessu

**Plik**: `tests/harness/mod.rs`

**Cel**: testy mają rejestrować to, co rejestruje `init`.

**Kontrakt**: `register_filter` ustawia `filter.<name>.process` i `required = true`.
Wariant „zawsze zawodzący" zostaje, ale realizowany innym sposobem niż usunięty
`--fail` — na przykład przez proces, który zgłasza `status=error`, albo przez
wskazanie nieistniejącej binarki. Dwa testy pilnujące `required = true` muszą
przejść bez zmiany sensu.

#### 6. Testy integracyjne pełnej ścieżki

**Plik**: `tests/filter_pipeline.rs`, `tests/filter_edge_cases.rs`

**Cel**: dowieść, że produkt działa przez prawdziwego gita.

**Kontrakt**: `init` w repozytorium testowym, wzorzec w `.git-xcrypt`, commit,
sprawdzenie że blob zaczyna się od magic, checkout, porównanie bajt w bajt,
`git status` czysty. Klon bez filtra pokazuje ciphertext.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- Blob w bazie obiektów zaczyna się od `\x00GITXCRYPT\x00`
- Plik w katalogu roboczym jest bajt w bajt równy oryginałowi po checkoucie
- `git status` po checkoucie jest czysty
- Klon bez konfiguracji filtra pokazuje ciphertext, nie plaintext
- Pusty plik i plik binarny przechodzą round-trip
- Filtr zwracający błąd przerywa `git add` i nie zostawia obiektu z plaintextem
- Jeden proces filtra obsługuje wszystkie pliki jednej operacji
- W drzewie nie ma już `__test-filter`, `transform` ani `run_filter`
- `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Weryfikacja ręczna

- `git add` na repozytorium z kilkuset plikami nie jest odczuwalnie wolniejszy
- Komunikaty na `stderr` są czytelne w oknie narzędziowym Git w IDE

---

## Strategia testowania

### Testy jednostkowe

- Kryptografia: determinizm, round-trip, wykrywanie manipulacji, fail closed na
  nieznanych polach nagłówka
- Wyprowadzanie klucza: stabilność `key_id`, rozdzielność materiału per suite
- Parser konfiguracji: dwie osie rozstrzygania, negacje, błędy
- EOL: heurystyka binarna, idempotencja normalizacji, tabela `autocrlf`/`eol`
- pkt-line: pakiety graniczne, ładunki binarne, dzielenie dużych ładunków

### Testy integracyjne

- Pełny przepływ przez prawdziwego gita w katalogu tymczasowym
- Pliki: pusty, jednobajtowy, tekstowy z CRLF, binarny z pełnym zakresem bajtów
- Klon bez klucza
- Filtr zawodzący i dowód, że plaintext nie trafia do bazy obiektów

### Testy właściwości

- `passthrough(x) == x` dla dowolnych bajtów
- `decrypt(encrypt(x)) == x`
- `encrypt(x) == encrypt(x)`

## Uwagi dotyczące wydajności

Zmierzony budżet: `git add -A` na 2000 plików to 540 ms bez filtra i 596 ms z
filtrem długożyjącym w Pythonie. Implementacja w Rust nie powinna wypaść gorzej.
Proces na plik dawał 12 105 ms i jest niedopuszczalny — dlatego rejestrujemy
wyłącznie `process`.

## Uwagi dotyczące migracji

Brak. Nic nie jest wydane, żadne istniejące repozytorium nie używa tego formatu.

## Referencje

- Format, kryptografia, idempotencja: `context/foundation/zalozenia.md`
- Pomiary catch-all i protokołu: tamże, §Integracja z git
- Roadmapa: `context/foundation/roadmap.md` → S-01

## Postęp

> Konwencja: `- [ ]` oczekujące, `- [x]` wykonane. Dołącz ` — <commit sha>` po zakończeniu kroku.

### Faza 1: Rdzeń kryptograficzny i format pliku

#### Automatyczne

- [x] 1.1 `cargo test` przechodzi
- [x] 1.2 `cargo clippy --all-targets -- -D warnings` przechodzi
- [x] 1.3 `cargo fmt --check` przechodzi
- [x] 1.4 Wektory RFC 5297 Appendix A przechodzą
- [x] 1.5 `decrypt(encrypt(x)) == x` dla pustego, jednobajtowego, tekstowego, binarnego
- [x] 1.6 `encrypt(x) == encrypt(x)` — determinizm
- [x] 1.7 Zmiana dowolnego bajtu bloba powoduje błąd deszyfrowania
- [x] 1.8 Podmiana `suite`, `flags` lub `key_id` powoduje błąd
- [x] 1.9 Pusty plaintext daje dokładnie 38 bajtów

#### Ręczne

- [x] 1.10 Wektory formatu faktycznie zamrażają format, a nie powtarzają implementację

### Faza 2: Przechowywanie klucza i komenda `init`

#### Automatyczne

- [x] 2.1 `init` tworzy klucz, wpisy w `.git/config` i sekcję w `.gitattributes`
- [x] 2.2 Powtórny `init` nie zmienia bajtów pliku klucza
- [x] 2.3 `init` bez klucza, ale ze śladami konfiguracji kończy się kodem `2`
- [x] 2.4 `init` poza repozytorium git kończy się kodem `2`
- [x] 2.5 Uprawnienia pliku klucza to `0600` (`#[cfg(unix)]`)
- [x] 2.6 Sekcja w `.gitattributes` jest idempotentna i nie niszczy treści użytkownika
- [x] 2.7 `cargo clippy --all-targets -- -D warnings` przechodzi

#### Ręczne

- [x] 2.8 Komunikat odmowy kieruje do właściwej komendy

### Faza 3: Konfiguracja, dopasowanie ścieżek i końce linii

#### Automatyczne

- [x] 3.1 Test właściwości `passthrough(x) == x`
- [x] 3.2 `sekrety/` obejmuje `sekrety/a/b.txt`
- [x] 3.3 Negacja wyłącza plik z szyfrowania
- [x] 3.4 Szeroki wzorzec bez atrybutów nie kasuje wcześniejszej deklaracji
- [x] 3.5 Nieznany atrybut i atrybut przy negacji kończą się błędem
- [x] 3.6 Pliki bootstrapu nigdy nie są szyfrowane
- [x] 3.7 Heurystyka `text=auto` zgodna ze zmierzoną regułą gita
- [x] 3.8 `normalize_to_lf` idempotentna, samotny `CR` nietknięty
- [x] 3.9 Ponowne szyfrowanie własnego ciphertextu zwraca go bez zmian
- [x] 3.10 Ciphertext z obcym `key_id` na ścieżce clean daje błąd `4`

#### Ręczne

- [x] 3.11 Ostrzeżenie przy `eol=` na ścieżce `-text` jest zrozumiałe

### Faza 4: Filtr długożyjący i usunięcie placeholdera

#### Automatyczne

- [x] 4.1 Blob zaczyna się od `\x00GITXCRYPT\x00`
- [x] 4.2 Plik po checkoucie jest bajt w bajt równy oryginałowi
- [x] 4.3 `git status` po checkoucie jest czysty
- [x] 4.4 Klon bez filtra pokazuje ciphertext
- [x] 4.5 Pusty plik i plik binarny przechodzą round-trip
- [x] 4.6 Filtr zwracający błąd przerywa `git add` i nie zostawia plaintextu
- [x] 4.7 Jeden proces obsługuje wszystkie pliki jednej operacji
- [x] 4.8 W drzewie nie ma `__test-filter`, `transform` ani `run_filter`
- [x] 4.9 `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Ręczne

- [x] 4.10 `git add` na kilkuset plikach nie jest odczuwalnie wolniejszy
- [x] 4.11 Komunikaty `stderr` czytelne w oknie Git w IDE

### Przegląd implementacji (2026-08-04)

Dwa przebiegi `/10x-impl-review`; pełny raport w `reviews/impl-review.md`.

#### Automatyczne

- [x] 5.1 Cztery drogi do jawnego sekretu w bazie obiektów zamknięte (ścieżka z białym
      znakiem na końcu, ścieżka spoza UTF-8, brak `.git-xcrypt`, niezweryfikowany tag)
- [x] 5.2 `text=auto` zgodne z gitem na samotnym `CR`; round-trip stabilny, `git status` czysty
- [x] 5.3 Determinizm potwierdzony empirycznie: identyczny blob przy `core.autocrlf`
      `false`/`true`/`input`; ścieżka clean nie czyta konfiguracji gita
- [x] 5.4 Zamrożone wektory formatu niezmienione
- [x] 5.5 Drugi przebieg: `looks_binary` jest portem `convert_is_binary` bajt w bajt,
      zweryfikowanym przeciw prawdziwemu gitowi na sześciu kształtach treści
- [x] 5.6 Reguła `text=auto` ma własne zamrożone wektory, w tym wektor przechodzący
      przez `decide::clean` — dotąd nie miała żadnych, wbrew `zalozenia.md`
- [x] 5.7 Ostrzeżenie „stored in the clear" tylko dla ścieżek wybranych: 301 plików
      dawało 301 ostrzeżeń, teraz jedno
- [x] 5.8 `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
      (139 testów), także w `--release`

#### Ręczne

- [ ] 5.9 Ścieżka spoza UTF-8 zweryfikowana na Linuksie — nie do odtworzenia na macOS
      (APFS wymusza UTF-8); czeka na nogę CI
- [ ] 5.10 Scenariusz regresyjny `core.autocrlf=true` na Windows
