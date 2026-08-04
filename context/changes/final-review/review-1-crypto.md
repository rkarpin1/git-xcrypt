# Final review, lens 1 of 3: cryptography, file format, key handling, hard rules

Data: 2026-08-04. Zakres: cały kod po S-01…S-06, ze szczególnym naciskiem na
kryptografię, format pliku, zarządzanie kluczem i twarde reguły z `AGENTS.md`.
Metoda: pomiar na prawdziwym gicie 2.55 w katalogach tymczasowych; każde
podejrzenie najpierw próbowano obalić, a każda naprawa ma test regresyjny
zweryfikowany jako czerwony na kodzie sprzed naprawy.

Bramka po naprawach: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test` — czysto, 400 testów.

---

## Findings

### F1 — `git-xcrypt diff` wypisywał klucz główny na `stdout`, kodem wyjścia 0

**Waga:** wysoka. Naruszenie twardej reguły „klucz nigdy na `stdout` poza `export-key`".

**Gdzie:** `src/keyfile.rs:37` — `holds_a_key`, przed naprawą jednolinijkowe
`content.starts_with(KEY_FILE_MAGIC) || content.starts_with(EXPORT_PREFIX.as_bytes())`.

**Scenariusz awarii (zmierzony).** `decode_portable` **celowo** akceptuje plik
klucza z komentarzami, pustymi liniami i wiodącymi spacjami — to kształt, jaki
klucz przybiera po przejściu przez menedżer haseł albo treść maila, i moduł ma
na to własny test (`a_portable_key_survives_comments_and_blank_lines`). Sprawdzenie
w sterowniku `diff` patrzyło natomiast wyłącznie na bajt zerowy. Jedna linia
`# my laptop, 2026-08-04` nad nagłówkiem wystarczała, żeby:

```
$ git-xcrypt diff ~/keys/annotated.key
# my laptop, 2026-08-04
git-xcrypt-key-v1 9aaf309c1f89b1e9
fUbg3U12CRcdyKS7roLU2ESHX4DKTx9k5mvg5EzF4Fg=
$ echo $?
0
```

Zmierzone trzy warianty — komentarz na górze, wiodąca pusta linia, wcięcie
spacjami — wszystkie wypisały klucz i **wszystkie trzy nadal importowały się jako
działający klucz** (`import-key` → `imported key 9aaf309c1f89b1e9`). Reguła
`refuse_private_path` tu nie pomaga: plik leży poza `.git/`.

To jest **dziura w naprawie C2 z przeglądu S-05**. Tamten przegląd słusznie
przeniósł zabezpieczenie z „gdzie plik leży" na „co plik zawiera, niezależnie od
katalogu, nazwy i dowiązań" — ale przypiął je do offsetu zero, więc parser i
odmowa rozjechały się co do tego, gdzie plik się zaczyna.

**Naprawa.** `holds_a_key` i `decode_portable` chodzą teraz przez wspólny
`significant_lines` (`src/keyfile.rs:76`), więc odmowa pokrywa **dokładnie** to,
co parser przyjmuje; rozjazd przestaje być możliwy konstrukcyjnie. Treść, która
nie jest UTF-8, nie może być przenośnym kluczem w ogóle, bo `read_portable`
czyta plik jako tekst.

**Testy regresyjne** (`src/keyfile.rs`):
- `every_shape_decode_portable_accepts_is_recognised_as_a_key` — pięć kształtów,
  każdy najpierw sprawdzany jako **importowalny**, potem jako rozpoznany.
  Zweryfikowany czerwony na kodzie sprzed naprawy.
- `ordinary_content_is_not_mistaken_for_a_key_file` — druga strona: fałszywe
  trafienie kosztuje użytkownika `git diff`, więc siedem kształtów zwykłej treści
  (w tym „nie-tekst" i wzmianka o formacie w prozie) musi przejść.

Sprawdzone po naprawie na prawdziwej binarce: wszystkie cztery warianty pliku
klucza → kod wyjścia 2, `stdout` pusty.

**Koszt wydajnościowy:** `from_utf8` po treści na ścieżce `diff`. Zmierzone na
plikach 50 MB (tekst i losowe bajty): bez mierzalnej różnicy — walidacja jest
o rząd wielkości szybsza niż odczyt pliku, który ta ścieżka i tak wykonuje.

---

### F2 — dwa testy, które `AGENTS.md` wskazuje jako straż nad `required = true`, nie pilnowały niczego

**Waga:** średnia (integralność zabezpieczenia testowego, nie działający błąd).

**Gdzie:** `tests/harness/mod.rs:152` — `break_filter`, które samo ustawiało
`filter.git-xcrypt.required = true`.

**Scenariusz awarii (zmierzony).** `AGENTS.md` mówi: „Regresji pilnują dwa testy
w `tests/filter_edge_cases.rs`". Te testy psują filtr przez wskazanie
nieistniejącej binarki — ale harness ustawiał przy tym flagę, czyli sam tworzył
warunek, którego ustanowienia przez `init` miał dowodzić. Pomiar: po usunięciu
linii `required` z `init::register_driver` **oba testy nadal przechodziły**.

Że stawka jest realna, sprawdzone osobno na gicie 2.55: bez flagi filtr, którego
git nie potrafi uruchomić, daje `git add` **kod wyjścia 0**, plik ląduje w
indeksie, a plaintext w bazie obiektów.

Uczciwie: jeden *inny* test (`deleting_the_declaration_stops_the_commit_instead_of_leaking`)
łapał to przypadkiem, z zupełnie innego powodu — więc regresja nie przeszłaby
niezauważona, ale zgłoszona byłaby pod nie tym tytułem.

**Naprawa.** `break_filter` nie ustawia już flagi. Zweryfikowane: z usuniętą
linią w `init` oba testy są teraz **czerwone**; z przywróconą — zielone. Komentarz
przy funkcji zapisuje dlaczego, żeby linia nie wróciła jako „porządek".

---

### F3 — format pliku klucza jest zadeklarowany jako zamrożony, a nie miał żadnego wektora

**Waga:** średnia. `zalozenia.md` §Zarządzanie kluczami: format pliku klucza jest
zamrożony „**tak samo mocno** jak format danych, bo leży u użytkowników i w
kopiach zapasowych". Format danych ma wektory; plik klucza nie miał żadnego.

**Scenariusz awarii (zmierzony).** Dwie prawdopodobne, jednolinijkowe zmiany
przechodziły przez **cały zestaw 392 testów na zielono**:

| zmiana | konsekwencja dla użytkownika | zestaw przed naprawą |
| --- | --- | --- |
| `KEY_FILE_VERSION` 1 → 2 | każdy plik klucza na dysku i w kopii zapasowej przestaje się otwierać („key file version 1 needs a newer git-xcrypt") | **zielony** |
| `STANDARD` → `URL_SAFE` base64 | każdy klucz wyeksportowany do menedżera haseł przestaje się importować | **zielony** |
| przestawienie bajtu wersji za klucz | jw., cichy rozjazd układu | zielony poza jednym testem ubocznym |

**Naprawa.** Pięć zamrożonych wektorów w `tests/format_vectors.rs`:
- `the_key_file_still_holds_the_frozen_bytes` / `the_frozen_key_file_still_reads_back`
  (`KEY_FILE_HEX`, linia 266) — plik binarny bajt w bajt, w obie strony;
- `the_portable_export_still_holds_the_frozen_text` / `the_frozen_portable_export_still_imports`
  (`EXPORT_TEXT`, linia 277) — forma przenośna w obie strony;
- `the_export_still_uses_the_frozen_base64_alphabet` (`ALPHABET_KEY`, linia 288).

Ostatni istnieje z powodu, który sam jest wart zapisania: `vector_key()` to same
bajty `0x2a`, a jego base64 nie zawiera **ani** `+`, **ani** `/` — czyli pierwszy
wektor przenośny okazał się ślepy na alfabet i podmiana silnika **nadal**
przechodziła. Drugi klucz (`0xe0..0xff`) ćwiczy oba znaki. Każdy z trzech
wariantów mutacji zweryfikowany jako czerwony przeciw własnemu wektorowi.

Dołożony też `the_key_id_in_a_file_header_is_the_one_the_key_file_names`:
`key_id` z nagłówka wektora danych (offset 14..22 = `fd2f0a5c2d19a55b`) jest tą
samą wartością, którą nazywa eksport — dwa formaty spotykają się w jednym polu
i teraz jest to powiedziane wprost.

**Uwaga o regule „nigdy nie commituj klucza".** Wektory zawierają klucze
`[0x2a; 32]` i `0xe0..0xff`. To publikowane stałe testowe, wypisane wprost w tym
samym pliku, z których wektory szyfrogramu i tak już wynikają — dokładnie jak
klucz z RFC 5297 Appendix A. Żaden z nich niczego nie otwiera. Reguła dotyczy
kluczy, które coś otwierają.

---

## Znaleziska świadomie odrzucone

- **Kopia plaintextu w `decide::clean` (bufor po normalizacji do LF) nie jest
  zeroizowana.** Twarda reguła mówi o materiale klucza, a ten jest pokryty w
  komplecie; na tej samej ścieżce ten sam plaintext leży jednocześnie w buforze
  pkt-line, w `Request::content` i w `Outcome::content`, więc zeroizacja jednej
  z czterech kopii nic nie kupuje, a sugeruje gwarancję, której ścieżka nie daje.
- **`hkdf` nie zeroizuje stanu HMAC zasianego kluczem głównym.** Zamknięcie tego
  wymaga wyjścia poza RustCrypto albo własnej konstrukcji — obie rzeczy zakazane.
  Dla porównania sprawdzone: `aes-siv` **zeroizuje** swój `encryption_key` w
  `Drop` (`siv.rs:265`). Własność zależności, nie nasza.
- **`getrandom` i `base64` nie są crate'ami RustCrypto.** Żaden nie jest
  prymitywem kryptograficznym: pierwszy to warstwa nad entropią systemu, na
  której RustCrypto samo stoi, drugi to kodowanie.
- **Uwierzytelnienie `key_id` przez AAD jest nieodróżnialne testem**, bo mutacja
  jest wyłapywana wcześniej przez jawne porównanie `key_id`. Bez konsekwencji
  bezpieczeństwa; jedyne pole nagłówka, które **może** się zmieniać w granicach
  tego, co `Header::parse` przyjmuje — bit `flags` — jest realnie dowiedzione
  jako uwierzytelnione przez `flipping_any_byte_is_detected`.
- **`Header::to_bytes` używa literałów 11/12/13 zamiast `MAGIC.len()`.** `MAGIC`
  jest zamrożone na zawsze, a wektory przypinają wynik.
- **Plik jawny zaczynający się od 11 bajtów magic blokuje `git add -A` w całym
  repozytorium** (zmierzone: `required = true` przerywa operację, nie tylko ten
  plik). To zapisane w `zalozenia.md` świadome ograniczenie, w kierunku fail
  closed.

---

## Zweryfikowane i czyste

Wszystko poniżej **zmierzone**, nie wywnioskowane z lektury.

**Pass-through jest tożsamościowy co do bajta.** 16 kształtów — pusty, 300 kB
losowych bajtów, niepełny i niepoprawny UTF-8, sama seria NUL, BOM, dokładnie
jeden pakiet pkt-line (65 516 B), jeden bajt ponad, dwa pakiety, plik bez
końcowego newline'a. Porównane **nie** z katalogiem roboczym (co myliłoby własną
konwersję gita z naszą), lecz z drugim repozytorium, w którym filtr nie jest
zarejestrowany w ogóle: identyczne identyfikatory blobów dla wszystkich.

**Determinizm.** 9 kombinacji `core.autocrlf` × `core.eol`, z `1`/`yes`/`on`
włącznie — ten sam identyfikator bloba dla pliku CRLF, LF i binarnego, i czysty
`git status` po checkoucie w każdej. Osobno: `autocrlf` przełączony w środku
historii repozytorium, treść przywrócona → ten sam blob co pierwotnie, czyli
zależna od indeksu heurystyka gita faktycznie **nie** została skopiowana.

**Narzut stały 38 bajtów** — co do bajta, na każdym kształcie, także po
normalizacji do LF.

**Nadużycia AEAD, obie strony przez prawdziwego gita.** Nieznany `suite`,
nieznana wersja, zarezerwowany bit `flags`, obcy `key_id`, przestawiony bajt SIV,
przestawiony bajt treści, plik ucięty, sam magic, plik krótszy niż nagłówek:
`git add` **kod 128**, nic w indeksie, żaden obiekt; `git checkout` **kod 128**,
plik nie powstaje. Plus jedyny wiersz przepuszczający — smudge bez magic —
przepuszcza treść i wypisuje ostrzeżenie na `stderr`, zgodnie z tabelą
idempotencji.

**Użycie API `aes-siv`.** Jednorazowe `decrypt`, nigdy `*_detached`. W crate:
tag porównywany przez `CtOutput` (czas stały), a przy niepowodzeniu plaintext
jest **ponownie szyfrowany** przed zwróceniem błędu — kształt RUSTSEC-2023-0096
jest nieosiągalny. AAD to faktycznie bajty `0..22`, i to bajty z dysku, nie
nagłówek odtworzony z oczekiwanych wartości.

**Klucz nigdy na `stdout`.** 17 wywołań komend: `stdout` ma 0 bajtów wszędzie
poza `status`, `diff`, `--help` i `--version` (wszystkie cztery z własnym
kontraktem). Ani jedno 8-bajtowe okno surowego klucza głównego, ani jego base64,
nie pojawia się na żadnym ze strumieni — w tym przy `diff` wskazującym wprost
plik klucza repozytorium.

**Higiena.** Zero `unsafe` (`unsafe_code = "forbid"` w `Cargo.toml`). Jedno
`expect` poza testami — `src/key.rs:121`, poprzedzone assertem, który czyni je
nieosiągalnym, i udokumentowane jako celowe fail-closed. Całe indeksowanie w
`Header::parse` i `keyfile::decode` jest za sprawdzeniem długości.

**Repozytorium SHA-256** — `init`, `add`, `commit`, `status`, `checkout`, czysty
`git status`. Bez paniki na ścieżce filtra.

---

## Do decyzji człowieka

Z tego przeglądu **nic nowego**. Otwarte pozycje z poprzednich przebiegów
(semantyka wzorców wobec `core.ignorecase` i normalizacji Unicode, pełne
rozwiązywanie atrybutów w `status`, płytkie klony wobec bramki CI, przeciążenie
kodu `5`, repozytoria bare, widoczność `stderr` filtra w RustRoverze) pozostają
bez zmian — żadna z nich nie leży w tym obiektywie.
