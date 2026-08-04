# Final review, lens 3 of 3: completeness and quality

Data: 2026-08-04. Zakres: cały projekt po S-01…S-06, obiektyw — **czego nie ma**.
Dwa poprzednie przeglądy szukały błędów w tym, co jest; ten pyta, co zostało
obiecane i nigdy nie powstało. Oba raporty (`review-1-crypto.md`,
`review-2-git.md`) przeczytane; ich znaleziska nie są tu powtarzane.

Metoda: konfrontacja pozycja po pozycji z `prd.md`, `zalozenia.md` i
`roadmap.md`; **mutacja** każdej twardej reguły i każdego zamrożonego kontraktu,
z odnotowaniem tych, które przeszły zielono; pomiar na prawdziwym gicie **2.55**
zamiast wnioskowania z lektury.

Bramka po naprawach: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test` — czysto, **422 testy** (277 `lib` + 145 integracyjnych), wobec 411
przed tym przebiegiem.

---

## 1. Czego brakowało wobec dokumentów założycielskich

### K1 — scenariusz akceptacyjny nie przechodził automatycznie, bo nie istniał jako test

**Waga: wysoka.** `zalozenia.md` §Kryteria akceptacji i `prd.md` §Success
Criteria → Primary opisują ten sam sześciopunktowy scenariusz i oba mówią, że
produkt liczy się za działający, gdy on **przechodzi automatycznie**. Każdy krok
był gdzieś pokryty, ale **nigdy w jednym przebiegu** — a dwa kroki nie były
pokryte wcale:

- **Kroku 3 (`push`) nie wykonywał żaden test.** `grep -rn "push\|bare" tests/`
  dawał wyłącznie komentarze. W całym repozytorium nie powstawało ani jedno
  repozytorium `--bare`.
- **Krok 4 („bloby w zdalnym repozytorium są zaszyfrowane") był sprawdzany w
  repozytorium źródłowym**, tym, w którym filtr właśnie je zapisał, przez
  `cat-file blob HEAD:<path>`. Klon powstawał z katalogu roboczego, nie z
  remote'u. `receive-pack` — który każdy przyjmowany obiekt ponownie czyta,
  pakuje i zapisuje — nie był ćwiczony ani razu.
- Scenariusz mówi o **dwóch** plikach z **dwóch** wzorców (`sekrety/haslo.txt` i
  `.env`); najbliższy test commitował jeden plik pasujący do obu naraz.

**Naprawa.** `tests/harness/mod.rs` dostał `BareRemote` (repozytorium gołe,
`push_to`, `blob_bytes`, `object_exists_for`, `clone_to`), a scenariusz istnieje
jako `tests/acceptance.rs::the_six_step_acceptance_scenario_passes_end_to_end` —
jeden test, sześć kroków, z prawdziwym `git push` i sprawdzeniem blobów **w
remote**. Dodatkowo asertuje, czego kryteria wymagają wprost, a co było
rozproszone: `.git-xcrypt` i `.gitattributes` zostają tam jawne, plik klucza
**nie jest** obiektem w bazie remote'u, klon przed `unlock` pokazuje ciphertext,
a po `unlock` `git status` jest czysty i zostaje czysty po `git add -A`.

### K2 — US-01 AC1 („czytelny błąd, nie panic") sprawdzało tylko kod wyjścia

`tests/key_transfer.rs::unlock_without_a_key_reports_a_missing_key` asertowało
`status.code() == Some(3)` i nic więcej. Kod 3 wyklucza panikę (ta dałaby 101),
ale nie mówi nic o tym, czy użytkownik dostaje coś, na czym może działać.

**Naprawa:** `tests/acceptance.rs::a_clone_without_the_key_reports_it_readably_rather_than_panicking`
— pełna ścieżka przez remote i klon, plus asercja, że komunikat nazywa brakującą
rzecz **i** wskazuje komendę, która ją naprawia. Dziś przechodzi na
`no repository key; run \`git-xcrypt init\`, \`unlock\` or \`import-key\``.

### K3 — `zalozenia.md` §Jakość i testy żąda scenariusza z `core.autocrlf=true`; słowo `autocrlf` nie występowało w `tests/` ani razu

Tabela z §Końce linii była odtworzona wyłącznie w teście jednostkowym
`eol::tests::the_measured_configuration_table_is_reproduced`, któremu wartości
konfiguracji podaje się **jako argumenty funkcji**. Most „konfiguracja gita →
`resolve_output`" nie był przekroczony przez żaden test, więc filtr czytający
niewłaściwy klucz wyglądałby poprawnie.

**Naprawa:** `tests/filter_edge_cases.rs::crlf_content_round_trips_under_every_autocrlf_setting`
— 12 kombinacji `core.autocrlf` × `core.eol` przez prawdziwego gita, jeden klucz
we wszystkich repozytoriach (inaczej różniłby się `key_id` w nagłówku i pomiar
nie znaczyłby nic). Sprawdza trzy rzeczy naraz: blob jest identyczny we
wszystkich konfiguracjach (determinizm międzymaszynowy), plaintext został
znormalizowany do LF przed szyfrowaniem, a katalog roboczy dostaje dokładnie ten
koniec linii, którego żąda tabela gita — i `git status` po checkoucie jest
czysty. Zweryfikowane: mutacje `autocrlf: None` i `core_eol: None` w
`filter.rs` czerwienią **wyłącznie** ten test.

### K4 — brak CI, przy dokumencie opisującym bramkę CI jako istniejącą

Katalogu `.github/` nie było w ogóle. `zalozenia.md` opisywał
`cargo test` / `clippy -D warnings` / `fmt --check` / `cargo audit` /
`cargo deny check licenses` na trzech platformach, a §Kryteria akceptacji mówiły
„na trzech platformach" — przy jednej realnie mierzonej. To zostawiało
nieweryfikowanymi luki pokrycia zgłoszone przez oba poprzednie przeglądy:
Windows (`EolMode::Native`, ACL pliku klucza, `atomic::replace` na pliku tylko do
odczytu) i Linux (ścieżki nie-UTF-8, których APFS nie przyjmuje).

**Naprawa:**

- `.github/workflows/ci.yml` — `test` na ubuntu/macOS/Windows (`--all-targets`
  plus doctesty), `lint` (`fmt --check`, `clippy --all-targets -- -D warnings`),
  `msrv` (pełny zestaw na zadeklarowanym `rust-version`), `audit`
  (`rustsec/audit-check`), `deny` (`licenses advisories sources bans`). Zadanie
  testowe wymusza `core.autocrlf=false` **globalnie na runnerze**, żeby checkout
  nie przepisał fixture'ów, i wypisuje wersję gita, bo git jest tu częścią
  systemu badanego.
- `.github/workflows/release.yml` — pięć targetów (Linux musl x86_64/aarch64,
  macOS x86_64/aarch64, Windows MSVC), sumy SHA-256, publikacja przy tagu `v*`,
  zadanie sprawdzające zgodność tagu z `Cargo.toml`. Podpisywania **nie ma** i
  jest to zapisane wprost, a nie zasymulowane krokiem, który podpisu nie daje.
- `deny.toml` — polityka licencyjna. Zweryfikowana uruchomieniem, nie deklaracją:
  `advisories ok, bans ok, licenses ok, sources ok`. Pierwsza wersja miała
  `[licences]` (pisownia brytyjska, `cargo deny` jej nie zna) i **nie ładowała
  się w ogóle** — czyli plik przepuszczałby wszystko. Poza parą MIT/Apache
  przyjęte świadomie: `Zlib` (`zlib-rs` przez `gix-zlib`) i `BSD-3-Clause`
  (`subtle`). Sekcja `[bans]` odmawia `openssl`, `ring`, `aws-lc-rs` i `boring` —
  `cargo deny` nie sprawdzi proweniencji kryptografii, ale może dopilnować, żeby
  oczywiste alternatywy nie weszły po cichu.

### K5 — `Cargo.toml` bez metadanych publikacyjnych i bez profilu release

Brakowało `description`, `repository`, `homepage`, `documentation`, `readme`,
`keywords`, `categories`, `exclude`, `rust-version` i `[profile.release]`.
Wszystkie dodane.

**MSRV zmierzony, nie założony.** `zalozenia.md` mówił „MSRV ustalony i
utrzymywany w CI (edycja 2024 wymaga min. Rust 1.85)", `AGENTS.md` mówił „MSRV
not pinned yet", a `Cargo.toml` nie mówił nic — trzy dokumenty, trzy stany.
Sprawdzone przez zainstalowanie łańcucha: **na 1.85 crate nie kompiluje się w
ogóle**, 12 × `E0658` — kod używa `let`-chain w warunkach `if`, stabilnych
dopiero od **1.88**. Cały zestaw testów przechodzi na 1.88, więc tyle wynosi
podłoga i tyle deklaruje `Cargo.toml`; zadanie `msrv` w CI trzyma ją tam.

`panic = "abort"` **nie** jest ustawione, i to celowo: `lock` i `unlock` chodzą
po drzewie roboczym plik po pliku, a abort ominąłby raport mówiący, które pliki
zostały już przepisane — dokładnie to, czego brak naprawiał przegląd 2 (F5).

### K6 — „testy właściwości" były listami 4–7 przypadków

`AGENTS.md` mówi, że `passthrough(x) == x` to **test właściwości, a nie
uprzejmość**, a `zalozenia.md` §Konstrukcja catch-all żąda go „dla **dowolnych**
bajtów". Realizacja: siedem zahardkodowanych próbek. `decrypt(encrypt(x)) == x`
i `encrypt(x) == encrypt(x)`: cztery. Zero `proptest`/`quickcheck` w projekcie.

**Naprawa.** `proptest` 1.11 jako `dev-dependency` — licencja `MIT OR
Apache-2.0`, zgodna z polityką, a cały graf po jego dodaniu przechodzi
`cargo deny check licenses`. Pięć właściwości, po 256 przypadków:

- `crypto::decrypting_what_we_encrypted_gives_the_plaintext_back` — round-trip na
  0–8 KiB dowolnych bajtów, z flagą 0 albo `FLAG_LF_NORMALIZED`, plus stały
  narzut 38 bajtów na dowolnym wejściu zamiast na czterech kształtach;
- `crypto::encrypting_the_same_bytes_twice_gives_the_same_blob` — determinizm;
- `decide::an_unselected_path_is_handed_back_byte_for_byte` — pass-through na
  0–16 KiB, po pięciu ścieżkach, z asercją, że nie ma też ostrzeżenia;
- `decide::content_without_our_magic_reaches_the_working_tree_unchanged` — druga
  strona pass-through, na ścieżce smudge;
- `decide::a_selected_path_survives_check_in_and_check_out` — pełny round-trip
  przez katalog roboczy: clean → smudge → clean daje ten sam blob.

Listy przypadków **zostają obok**. Nazywają kształty, które kiedyś psuły —
plik pusty, jeden bajt, wszystkie 256 wartości, sam magic — a generator, który
akurat ich nie wylosuje, po cichu przestałby je pokrywać.

Że nie są ozdobą: mutacja „clean wymusza `TextMode::Text` zamiast czytać
deklarację" czerwieni **wyłącznie**
`a_selected_path_survives_check_in_and_check_out`. Lista przypadków jej nie
łapie, bo trzeba trafić w treść z `\r\r\n`.

`proptest-regressions/` celowo **nie** jest w `.gitignore`: gdy CI znajdzie
kiedyś prawdziwy kontrprzykład, jego nasiono ma trafić do repozytorium.

---

## 2. Mutacje, które przeszły zielono

27 mutacji na twardych regułach i zamrożonych kontraktach. Zielone dwie.

### M15 — próg 128 : 1 w `looks_binary` nie był pilnowany przez nic

**Waga: średnia-wysoka.** `src/eol.rs:71`, `(printable >> 7) < nonprintable`.
Reguła jest w `eol.rs` opisana jako **zamrożona wraz z formatem** — jej zmiana
przesuwa granicę tekst/binarny, więc zmienia, które pliki są normalizowane do
LF, więc **przepisuje ciphertext istniejących plików**. Mimo to:

| mutacja | zestaw 411 testów |
| --- | --- |
| `>> 7` → `>> 6` | **zielony** |
| `>> 7` → `>> 8` | **zielony** |

Istniejące wektory (`2560 B` bajtów wysokich, `2400 B` znaków sterujących)
leżą daleko od granicy i przeżywają obie zmiany.

**Zmierzone na git 2.55** (`* text=auto`, `core.autocrlf=true`, treść
`'A' × printable + 0x01 × nonprintable + CRLF`, werdykt czytany po tym, czy CRLF
przeżyło w blobie):

| drukowalne : niedrukowalne | git |
| --- | --- |
| 127 : 1 | binarny |
| 128 : 1 | **tekst** |
| 255 : 2 | binarny |
| 256 : 2 | **tekst** |
| 1023 : 8 | binarny |
| 1024 : 8 | **tekst** |

**Naprawa:** `eol::tests::the_ratio_sits_exactly_where_gits_does` przypina
wszystkie sześć par plus 129 : 1. Obie mutacje zweryfikowane jako **czerwone**
przeciw niemu.

### M13 — AAD odtworzone z nagłówka zamiast bajtów z dysku: **mutant równoważny, odrzucone**

`crypto.rs:63` mówi „associated data muszą być bajtami faktycznie na dysku, nie
nagłówkiem odtworzonym z oczekiwanych wartości — odtworzenie ukryłoby
przestawiony bajt". Podmiana na odtworzony nagłówek przechodzi cały zestaw
zielono. **To nie jest luka:** `Header::parse` przyjmuje dokładnie jeden kształt
bajtów `0..22` (magic musi być dosłowny, wersja i suite muszą równać się
stałym, nieznany bit `flags` jest odrzucany, `key_id` przepisany), więc
`to_bytes()` odtwarza je co do bajta i różnicy **nie da się zaobserwować**.
Gwarancja jest konstrukcyjna i broni przed przyszłym rozluźnieniem parsera; test
na nią nie istnieje, bo istnieć nie może. Zgodne z odrzuceniem z przeglądu 1.

### Mutacje, które wyszły czerwono (wybór)

`required = true` → `false`, rejestracja jako `clean`/`smudge` zamiast `process`,
`cachetextconv` → `true`, catch-all zawężony do `*.env`, każda z pięciu stałych
kodów wyjścia, oba `info` HKDF, tryb pliku klucza `0600` → `0644`, obie twarde
wykluczenia (`.gitattributes`, `.git-xcrypt`), `text=auto` zawsze normalizujące,
normalizacja samotnego `CR`, `EolMode::Crlf` piszące LF, clean przepuszczający
treść bez deklaracji, `already_encrypted` pomijające weryfikację tagu, filtr
ignorujący `core.autocrlf` i `core.eol`.

**Sprawdzone naprawy z poprzednich przebiegów.** Naprawa F2 z przeglądu 1
działa: z usuniętą linią `required` z `init::register_driver` oba testy z
`tests/filter_edge_cases.rs`, które `AGENTS.md` wskazuje jako straż nad tą flagą,
są **czerwone** (plus trzeci, `deleting_the_declaration_stops_the_commit_instead_of_leaking`).

**Uwaga metodologiczna, warta zapisania.** Harness mutacyjny przywracał plik
przez `mv plik.bak plik`, co cofa `mtime` — cargo uznawał wtedy artefakt za
aktualny i **nie przebudowywał**, zostawiając zmutowany `rlib` w `target/`.
Objawiło się to fałszywą czerwienią w `format_vectors` długo po zakończeniu
mutacji. Werdykty RED i GREEN z samego przebiegu mutacji są tym nietknięte
(mutacja dostaje świeży `mtime`, więc jest kompilowana), ale każdy pomiar **po**
przebiegu wymaga `touch` na źródłach. Bramka końcowa uruchomiona po wymuszonej
przebudowie.

---

## 3. Pozostałe znaleziska

### F1 — `status` opisywał nieaktualną sekcję `.gitattributes` jako niedogodność, a nie jako utratę pliku

**Waga: średnia-wysoka.** Komunikat jest tu częścią zabezpieczenia, nie ozdobą —
roadmapa mówi to wprost przy S-06.

**Gdzie:** `src/commands/status.rs:1056`, `stale_section_note`. Treść przed
naprawą: *„Nothing is stored in the clear over this, but a clone's `unlock` will
rewrite them and leave `git status` dirty."*

**Zmierzone na git 2.55, pełna ścieżka.** Wzorzec dopisany do `.git-xcrypt` bez
uruchomienia `sync`, plus zwyczajna cudza linia `secrets/** text` w
`.gitattributes`, plik 2 MB:

```
$ git add -A
warning: in the working copy of 'secrets/db.env', CRLF will be replaced by LF …
$ echo $?
0
$ git cat-file -s :secrets/db.env
2000004                       ← powinno być 2000038; git zjadł 34 bajty CR
$ git commit -qm x && rm secrets/db.env && git checkout -- secrets/db.env
git-xcrypt: secrets/db.env: authentication failed; the file has been altered
fatal: secrets/db.env: smudge filter git-xcrypt failed
$ ls secrets/
                              ← pusto. Blobu nie odszyfruje już nikt, nigdy.
```

Selekcja działa natychmiast (filtr czyta `.git-xcrypt`, nie `.gitattributes`), co
sprawia, że linie zarządzane **wyglądają** na ozdobę. `-text` jest tym, co trzyma
własną konwersję CRLF gita z dala od ciphertextu. Odpalenie wymaga cudzego
atrybutu `text` — nasze magic zaczyna się od NUL, więc `text=auto` i
`core.autocrlf` same widzą binaria i nie ruszają pliku — dlatego zostaje **notą**,
nie luką z kodem `5`. Ale nie jest kosmetyką.

**Naprawa.** Nota nazywa teraz brakujące `-text`, mechanizm i skutek („corrupts
the blob silently and costs the file at checkout"), zachowując poprzednie zdanie
o brudnym `git status` po klonie.

**Test regresyjny:**
`tests/status_command.rs::a_stale_section_is_reported_as_the_corruption_it_risks_not_as_a_tidiness_nag`
— najpierw **odtwarza uszkodzenie** przez prawdziwego gita (blob nie ma rozmiaru
`38 + treść`, checkout nie tworzy pliku), potem sprawdza treść noty.
Zweryfikowany jako czerwony przeciw poprzedniemu brzmieniu.

### F2 — test nazwany „jeden proces filtra obsługuje całą operację" nie liczył procesów

**Waga: średnia.** `tests/filter_pipeline.rs:79`. Ciało sprawdzało wyłącznie, że
25 plików wyszło zaszyfrowanych. Regresja do procesu na plik — czyli do
**22-krotnego spowolnienia, które `zalozenia.md` nazywa dyskwalifikującym** —
przechodziła go zielono, a nic w całym repozytorium nie liczyło procesów filtra.

**Naprawa, dwie warstwy.**

- `the_filter_is_registered_for_the_long_running_protocol_only` (przenośne):
  `filter.git-xcrypt.process` jest ustawione, a `clean` i `smudge` **nie są**.
  Czerwony przy mutacji `init` rejestrującej parę per-plik.
- `one_filter_process_serves_a_whole_operation` (`#[cfg(unix)]`, bo używa skryptu
  powłoki): rejestracja wskazuje wrapper, który dopisuje linię przy każdym
  starcie i dopiero potem staje się prawdziwą binarką. Wrapper i licznik leżą
  **poza** drzewem roboczym, inaczej `git add -A` zamiotłoby je do mierzonego
  commita.

**Zmierzone**, to samo repozytorium, 25 sekretów: protokół długożyjący **1**
start, prawdziwy sterownik per-plik **27** startów. Asercja `starts < FILES`
rozróżnia je z zapasem.

### F3 — jedyny test bez asercji

`gitconfig::tests::unsetting_an_absent_key_is_not_an_error` opierał się wyłącznie
na `.expect()` na wyniku `unset`. Implementacja kasująca całą sekcję przeszłaby
go — a razem z sekcją znika `filter.git-xcrypt.required`. Ścieżka nie jest
teoretyczna: `lock` woła `unset` na repozytorium, które mogło nigdy nie mieć
sterownika `diff`, i jest to komenda, po której użytkownikowi nie zostaje klucz
do naprawienia czegokolwiek.

**Naprawa:** przemianowany na `unsetting_an_absent_key_leaves_its_neighbours_alone`,
zapisuje sąsiadów, wykonuje `unset`, przeładowuje i sprawdza, że oba przeżyły.

### F4 — rozjazd dokumentacji z kodem

Naprawione w dokumentach; poniżej to, co było nieprawdą, nie tylko
nieaktualnością.

| Gdzie | Twierdzenie | Stan faktyczny |
| --- | --- | --- |
| `README.md` | „No user-facing command exists yet" | dziewięć podkomend, cały zestaw v0.1 |
| `zalozenia.md` ×2 | „linie per wzorzec są kosmetyczne … pomyłka nie kosztuje sekretu" | kosztuje **plik**, zmierzone wyżej (F1) |
| `zalozenia.md` ×2 | „smudge nie czyta `.git-xcrypt` w ogóle" | czyta `eol=` i to, czy ścieżka jest zadeklarowana; sprzeczne z własnym zapisem, że `eol=` celowo nie trafia do nagłówka |
| `zalozenia.md` | „dopasowaniem zajmuje się `gix-ignore`" | tego crate'a nie ma w `Cargo.toml`; semantykę pliku odtwarza `src/config.rs` nad `gix-glob` |
| `zalozenia.md` ×2 | „ścieżkę dostaje przez `%f`" | przy `process` ścieżka przychodzi jako `pathname=`, surowe bajty |
| `zalozenia.md` | „filtry `clean`/`smudge`/`diff` zarejestrowane w `.git/config`" | cztery klucze, `process` + `required` + `textconv` + `cachetextconv = false`; `clean`/`smudge` nie są rejestrowane nigdy |
| `zalozenia.md` | „`gix-config` daje **pełną** precedencję wraz z `includeIf`" | trzy zmierzone dziury (przegląd 2), wszystkie dotyczące EOL |
| `zalozenia.md` | „MSRV ustalony i utrzymywany w CI" | nie było ani MSRV, ani CI; `AGENTS.md` mówił coś przeciwnego |
| `zalozenia.md` | „powstają binaria dla Windows, macOS i Linux" | nie było `.github/` |
| `zalozenia.md` | odbiorcy opisani w czasie teraźniejszym | poza zakresem v0.1, sprzeczne z dwoma innymi miejscami tego samego pliku |
| `zalozenia.md` | reguła `looks_binary` bez samotnego `CR`, bez `DEL`, bez progu 128 : 1, bez odstępstwa na `SUB` | uzupełnione w komplecie, z odesłaniem do S-08 |
| `zalozenia.md` | „ślady wcześniejszej konfiguracji … `.git-xcrypt` **w HEAD**" | kod patrzy na **drzewo robocze**; jest ostrożniejszy, dokument dopasowany do kodu |
| `zalozenia.md` | „`status` — trzy zadania", po czym cztery wypunktowania | cztery, plus piąte (`undetermined`), którego nie było nigdzie w foundation |
| `zalozenia.md` §Zakres MVP | brak `diff` i `process` na liście komend; brak `sync --check` | dopisane |
| `AGENTS.md` | „`S-07` … is what is left of v0.1" | **S-08 musi wejść pierwsze**, bo `looks_binary` zamraża się z formatem |
| `roadmap.md` | pięć elementów ze statusem `proposed` | wszystkie zrobione i dwukrotnie przejrzane |
| `prd.md` | otwarte pytanie 7 (wiele kluczy, rotacja) | rozstrzygnięte w `zalozenia.md` §Zakres MVP jako poza zakresem v0.1 |

Nieudokumentowane wcześniej decyzje implementacyjne, dopisane do `zalozenia.md`:
`cachetextconv = false` jako decyzja **bezpieczeństwa** (przy `true` git trzyma
odszyfrowaną treść jako bloby w `.git/`, przeżywające `lock`, a `true` w
`~/.gitconfig` jest dziedziczone); `diff` odmawiający po **treści** pliku, nie po
położeniu; sekcja `undetermined` i to, że kończy kodem `5`; brak obsługi
`GIT_DIR` + `GIT_WORK_TREE` bez `.git` w drzewie.

`roadmap.md` zaktualizowana w całości: statusy, `Streams`, `Baseline` oznaczone
jako zdjęcie historyczne, `Backlog Handoff` (S-08 pierwsze, potem S-07), `Done`
z lekcjami, `Open Roadmap Questions`.

### F5 — wydajność: pomiar zamiast deklaracji

`git add -A`, 2050 plików, ten sam sprzęt, trzy powtórzenia:

| | rep 1 | rep 2 | rep 3 |
| --- | --- | --- | --- |
| bez filtra | 66 ms | 67 ms | 66 ms |
| catch-all, filtr długożyjący | 105 ms | 103 ms | 109 ms |

Około **+19 µs na plik**. Względne +58% wygląda gorzej niż zapisane w projekcie
+10%, ale tamten pomiar miał podstawę 540 ms na wolniejszej maszynie — koszt
bezwzględny jest tego samego rzędu i nieporównywalny z 22× dla procesu na plik.
Liczby wystarczają, żeby domknąć otwarte pytanie 5 z PRD („próg liczbowy dla
NFR") bez nowych pomiarów; brakuje wyłącznie decyzji, ile wolno.

### F6 — jakość kodu Rust: bez znalezisk

Sprawdzone i czyste. Poza modułami testowymi w całym `src/` jest **jeden**
`expect` (`key.rs:121`), poprzedzony assertem, który czyni go nieosiągalnym, i
udokumentowany jako celowe fail-closed; zero `unwrap()`, `panic!`, `unreachable!`
i `todo!`. `unsafe_code = "forbid"` w `Cargo.toml`. Błędy przez `thiserror` z
mapowaniem na zamrożoną tabelę kodów w jednym miejscu (`lib.rs:84`), zweryfikowanym
mutacyjnie co do każdej z pięciu wartości. `# Errors` obecne na funkcjach
publicznych zwracających `Result`. `clippy --all-targets -- -D warnings` czysto.

---

## 4. Świadomie odrzucone

- **AAD odtworzone z nagłówka (M13)** — mutant równoważny, uzasadnienie wyżej.
- **Zeroizacja plaintextu na ścieżce filtra** — odrzucone przez przegląd 1 z
  powodem, który nadal obowiązuje; nic w tym obiektywie tego nie zmienia.
- **Rozbicie `tests/acceptance.rs` na testy per krok** — czytelniejszy raport z
  błędu, ale scenariusz akceptacyjny ma być jedną czerwoną linią, gdy obietnica
  przestaje być prawdziwa.
- **Uczynienie nieaktualnej sekcji `.gitattributes` luką z kodem `5`** — trafienie
  wymaga cudzego atrybutu `text`, a podniesienie noty do luki zapaliłoby bramkę
  w repozytoriach, w których nie dzieje się nic złego. Zostaje notą z uczciwym
  opisem skutku.
- **`proptest` na ścieżce `smudge` z generowaniem poprawnego ciphertextu** —
  generator musiałby najpierw zaszyfrować, czyli powtórzyłby round-trip, który
  już jest pokryty.
- **Zadanie CI na `cargo semver-checks`** — crate nie ma jeszcze wydanej wersji,
  więc nie ma z czym porównywać.

---

## 5. Do decyzji człowieka — komplet z trzech przebiegów

Zebrane w jedno miejsce, bo to ostatni przegląd. Pozycje 1–5 pochodzą z
przeglądu 2, 6–8 z wcześniejszych przebiegów, 9–12 z tego. Wszystkie są też
dopisane do `zalozenia.md` §Otwarte decyzje.

1. **Kod wyjścia `5` jest przeciążony.** `status` zwraca go i dla realnej
   ekspozycji, i dla `undetermined` (klon płytki, klon częściowy, split index,
   nieczytelny indeks, brak `.git-xcrypt`). Zmierzone: zdrowy
   `git clone --depth 1` kończy `5`, a `actions/checkout` jest domyślnie
   płytkie — **domyślna konfiguracja CI nie przechodzi tej bramki**. Tabela
   kodów jest zamrożona i nie ma kodu „nie dało się ustalić". Albo nowy kod,
   albo degradacja płytkiego/częściowego klonu do noty.
2. **Czy `status` ma rozwiązywać atrybuty gita, zamiast je nazywać.** Pełna
   odpowiedź na „czy git uruchomi filtr dla tej ścieżki" wymaga nowej zależności
   (`gix-attributes`).
3. **Kolizja kodu `1`.** Przy `lock`: odmowa użytkownika, błąd użycia i porażka
   zapisu w połowie. Przy `sync --check`: „sekcja nieaktualna". Rozróżnienie
   wymaga ruszenia zamrożonej tabeli.
4. **Skracanie nazwy pliku tymczasowego** dla nazw ≥ 224 B oznacza, że residuum
   po zabitym przebiegu na takim pliku może nie zostać zamiecione przez `lock`.
   Bezwarunkowa obietnica „po `lock` nie zostaje żaden plaintext" wymagałaby
   innego schematu nazw, np. rejestru residuum w `.git/`.
5. **`GIT_CONFIG_PARAMETERS` i `includeIf` w konfiguracji globalnej** — dziury w
   `gix-config`. Domknięcie: własny parser, spawnowanie `git config` (zakazane)
   albo zgłoszenie upstream.
6. **Semantyka wzorców wobec `core.ignorecase` i normalizacji Unicode nazw
   plików** — nie sprawdzone; ma znaczenie na macOS i Windows.
7. **Czy odtwarzamy ostrzeżenie `core.safecrlf`** dla plików o mieszanych końcach
   linii, które nie przetrwają round-tripu.
8. **Czy `stderr` filtra jest wystarczająco widoczny w oknie Git w JetBrains**,
   żeby ostrzeżenie nie ginęło. Do sprawdzenia empirycznie, przez człowieka.
9. **Próg liczbowy dla NFR wydajnościowego.** Pomiary są (F5); brakuje decyzji,
   ile wolno.
10. **Podpisywanie artefaktów wydania.** `release.yml` daje sumy SHA-256 i nic
    więcej. PRD FR-011 notuje, że niepodpisana binarka narzędzia kryptograficznego
    to nowy wektor zaufania. Do rozstrzygnięcia **przed** pierwszym publicznym
    wydaniem, razem z pytaniem o build odtwarzalny.
11. **Kolejność S-08 przed S-07 jest wiążąca.** `looks_binary` zamraża się z
    pierwszym wydaniem: po nim poprawka na końcowy `SUB` przestaje być poprawką,
    a staje się zmianą, która przepisuje ciphertext istniejących plików i wymaga
    nowego `suite`. Roadmapa i `AGENTS.md` mówią to teraz wprost.
12. **Kopia zapasowa jedynego pliku klucza** (PRD Open Question 2) pozostaje
    otwarta. Cztery zabezpieczenia już są — ostrzeżenie przy `export-key`,
    potwierdzenie `yes` przy `lock` z `key_id`, odmowa przy niezacommitowanych
    zmianach, odmowa przy innych podłączonych worktree — ale żadne z nich nie
    tworzy kopii.

Do tego dwie rzeczy, które nie są decyzjami, tylko czekają na człowieka:
**żaden z workflow nie został jeszcze uruchomiony przez GitHub Actions**, więc
Windows i Linux nadal nie mają ani jednego realnego przebiegu; oraz `tech-stack.md`
mówi o wydaniu sterowanym ręcznie i tak też jest skonfigurowany `release.yml`
(tag `v*`), co warto potwierdzić przed pierwszym tagiem.
