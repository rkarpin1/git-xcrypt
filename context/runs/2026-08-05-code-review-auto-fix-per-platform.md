# emi-code-review-auto-fix — 2026-08-05, po jednej rundzie na platformę

Parametry: 3 rundy × 3 etapy, obiektywy Windows / Linux / macOS. Gałąź `master`,
SHA startowe `c028ffd`. Rundy ślepe na siebie — żadna nie dostała raportu poprzedniej.

Baza przed przebiegiem: fmt OK, clippy 0 ostrzeżeń, **443 testy**, `licenses ok`,
oba cele skrośne kompilują się.

Bramki (sześć, każda runda po każdej naprawie):
`cargo fmt --check` · `cargo clippy --all-targets -- -D warnings` · `cargo test` ·
`cargo deny check licenses` · `cargo check --all-targets --target x86_64-pc-windows-msvc` ·
`cargo check --all-targets --target x86_64-unknown-linux-gnu`

**Ograniczenie warsztatu, zapisane wprost:** przebieg wykonano na macOS. Rundy 1 i 2
mogły Windows i Linuksa wyłącznie kompilować i sparametryzować — nie uruchomić. Każdy
taki przypadek jest niżej nazwany.

## Runda 1 — Windows

**Kandydaci 9 → ustalenia 3** (etap 1), 4 → 0 (adwersarz), 1 domknięcie pokrycia (etap 3).

| | |
|---|---|
| `2ea1049` | **Sekcja zarządzana renderowana zawsze z LF.** Zmierzone na żywym gicie: klon z `core.autocrlf=true` (domyślne w Git for Windows), sekcja aktualna co do bajta → `sync --check` kod **1**, `status` wypisywał **nieprawdziwą** notę o korupcji ciphertextu, `sync` zostawiał brudny `git status` bez wyjścia. Bramka CI alarmująca na domyślnej konfiguracji platformy to bramka wyłączona — ten sam argument, który dał `status` kod `6`. |
| `33e30c2` | **Bezwarunkowy `replace('\\', "/")` na ścieżce binarki w `init`.** Na uniksie backslash jest zwykłym znakiem nazwy, więc binarka w `tools\v2/git-xcrypt` rejestrowała się jako ścieżka nieistniejąca; `init` kończył 0, a przy `required = true` każda kolejna operacja gita padała. |
| `f6b74ce` | **Dokumentacja obiecywała ACL na Windows i bezwarunkowe `0600`.** Nieprawda w każdym buildzie — `.mode(0o600)` stoi wyłącznie w `#[cfg(unix)]`. Zapis pochodził ze scaffoldu i nigdy nie został zaimplementowany. Dotyka twardej reguły o kluczu. |
| `759771f` | Domknięcie pokrycia: `EolMode::Native` / `cfg!(windows)` sparametryzowane przez `apply_where`, więc gałąź windowsowa jest testowalna z macOS. Zero zmian zachowania. |

Odrzucone m.in.: nazwy urządzeń DOS (`CON.env` — `CreateFile` nie pozwala takiego pliku
utworzyć), `to_string_lossy` na niesparowanym surogacie (git nie potrafi takiej nazwy
śledzić), pliki read-only (obie ścieżki zawodzą głośno i w bezpieczną stronę).

## Runda 2 — Linux

**Kandydaci 6 → ustalenia 1** (etap 1), 4 → 0 (adwersarz), 2 → 2 (kompletność).

| | |
|---|---|
| `84a9269` | **Polecenie naprawcze dla `git-filter-repo` renderowane stratnie.** Na ext4 `secrets/bad\xff.env` jest legalną nazwą; `status` znajduje wyciek poprawnie (bo na bajtach), po czym drukuje polecenie z `U+FFFD`, które **parsuje się, wykonuje, nie dopasowuje niczego i kończy zerem** — użytkownik zostaje z przekonaniem, że blob zniknął. |
| `244ba17` | **`.git-xcrypt` z bajtem spoza UTF-8 dawał błąd bez nazwy pliku.** Zmierzone: git obok wypisywał `fatal: secrets/db.env: clean filter failed` nad zupełnie zdrowym plikiem. W tym stanie każda operacja gita jest martwa, a obie widoczne wiadomości wskazują nie ten plik. Trzy sąsiednie moduły robiły to poprawnie; `Config::load` był jedynym wyjątkiem. |
| `72bc381` | Test `#[cfg(target_os = "linux")]` prowadzący `secrets/pa\xffssword.env` przez pełny cykl: `git add` → blob → `status` → `export-key` → `lock --yes` → `unlock`. **Agent go nie uruchomił i uruchomić nie mógł** — APFS odrzuca takie nazwy. Zweryfikowano, że kompiluje się pod celem linuksowym; sekwencja przećwiczona z nazwą ASCII. |

Obalone **pomiarem**, nie rozumowaniem: hipoteza, że backend `reftable` da pusty zbiór
referencji i `status` wyjdzie `0` nad jawnym sekretem w historii — zmierzone, kończy `6`
z werdyktem `undetermined`. Twarda reguła trzyma.

Nierozstrzygnięte: binarka zainstalowana pod ścieżką spoza UTF-8 (`init.rs:350`) — nie da
się takiej ścieżki utworzyć na APFS, a poprawka zależy od tego, czy `gix-config` uniesie
wartość spoza UTF-8.

## Runda 3 — macOS

Jedyna runda, w której **wszystko dało się wykonać**. Kandydaci 5 → ustalenia 2 (etap 1),
3 → 1 (adwersarz, na własnej naprawie), 0 → 0 (kompletność).

| | |
|---|---|
| `bb46a0a` | **`core.ignorecase` — plaintext w bazie obiektów przy zielonym `status`.** Zmierzone: `.git-xcrypt` z `*.env`, plik `top.ENV` → `git add -A` kod 0, plaintext zapisany, a `git check-attr` odpowiada `filter=git-xcrypt` z **naszej własnej** sekcji zarządzanej. Złamanie reguły „ani węższy, ani szerszy" w kierunku szerszym. Kontrola raportuje `undetermined`, kod **6** — selekcja nie drgnęła, bo to otwarta decyzja właściciela. |
| `60699ea` | **`lock` kasował klucz nad czytelnym plaintextem.** Po `mv secrets Secrets` indeks trzyma `secrets/db.env`, dysk `Secrets/`, `git status` milczy, a `lock --yes` pisał „no file here is declared", wychodził **0**, kasował klucz i zostawiał sekret jawny. `gitindex.rs` opisywał ten przypadek twierdząc, że „lock refuses rather than proceeds" — **nie odmawiał**. |
| `4e74a22` | **Błąd we własnej naprawie z `60699ea`**, złapany przez etap adwersarza: bariera czytała *każdą* porażkę `open` jako „pliku nie ma". `chmod 000` na zadeklarowanym pliku → `lock --yes` pomijał go, kasował klucz, sekret czytelny po przywróceniu trybu. „Nie dało się ustalić" zaraportowane jako „nic złego się nie dzieje", przed krokiem nieodwracalnym. |

Wszystkie **siedem** commitów z rund 1–2 uruchomione i zmutowane na tej maszynie: każdy
potwierdzony pomiarem, żaden nie cofnięty.

## Weryfikacja niezależna (sesja główna, nie agenci)

Mutacje przeprowadzone poza agentami, na kodzie zacommitowanym:

- `line_ending_of` → zawsze LF: czerwony `a_crlf_file_is_rewritten_in_its_own_spelling…`
- gałąź windowsowa `EolMode::Native` → zawsze LF: czerwony `the_native_mode_writes_what_each_platform_asks_for_and_still_round_trips`
- **`refuse_if_a_declared_file_is_still_open` → no-op: `lock --yes` kod `0`, katalog kluczy pusty, `hunter2-secret` czytelne na dysku.** Z barierą: kod `2`, klucz zachowany, komunikat nazywa plik i przyczynę.

Test linuksowy obejrzany pod kątem zębów: konstruuje realną nazwę spoza UTF-8, asertuje
magic w blobie, narzut dokładnie `38 + len`, kod `status`, szyfrowanie po `lock` i
identyczność po `unlock`. Nie jest pusty.

## Bilans

| | |
|---|---|
| Commity przebiegu | 10 (`2ea1049`…`4e74a22`) |
| Kandydaci → ustalenia | ~34 → 10 |
| Odrzucone | ~19 |
| Nierozstrzygnięte | 3 |
| Cofnięte | 0 |
| Testy | 443 → **455** |
| Bramki | wszystkie sześć zielone |

Stosunek odrzuconych do naprawionych ~2:1 — Faza B1 odrzucała, a nie potwierdzała własne
podejrzenia. Etap adwersarza rundy 3 znalazł błąd we własnej naprawie z tej samej rundy,
co jest dowodem, że kontrola działała.

## Co zostało dla człowieka

1. **Otwarta decyzja 13 — semantyka wzorca wobec `core.ignorecase`.** Teraz **zmierzona**
   i dopisana do `zalozenia.md`. Zwinięcie selekcji znaczy czytanie niewersjonowanego
   `core.ignorecase` na ścieżce clean, więc to samo repozytorium szyfrowałoby inny zbiór
   plików na macOS niż na Linuksie — dokładnie argument, którym `zalozenia.md` wyklucza
   `core.autocrlf` z tej ścieżki. Do rozstrzygnięcia **przed pierwszym wydaniem**.
2. **`PATH_MAX` = 1024 na macOS wobec `atomic::temporary_name`.** Zmierzone: ścieżka 997 B
   → `lock` kończy `File name too long`, kod 1, w kółko, a komunikat obiecuje, że ponowne
   uruchomienie pomoże. Klucz nie jest kasowany, więc kierunek bezpieczny. Bez naprawy,
   bo każdy wariant jest gorszy (plik tymczasowy poza katalogiem celu → EXDEV i plaintext
   poza repozytorium; zapis nieatomowy → okno półzapisanego sekretu).
3. **Binarka pod ścieżką instalacyjną spoza UTF-8** (`init.rs:350`) — nierozstrzygnięte,
   wymaga ext4 albo decyzji, czy `init` ma odmawiać kodem `2`.
4. **Zmiana zachowania:** `status` na macOS i Windows może odtąd wyjść `6` tam, gdzie
   wychodził `0`. Koszt dziś zerowy — `S-07` nie ruszył, nie istnieje odbiorca poza tym
   repozytorium.
5. Niesprawdzalne z macOS: faktyczne ACL pliku klucza na Windows (zawężenie wymaga
   `windows-sys` i `unsafe`, czyli złamania `unsafe_code = "forbid"` — decyzja o zakresie,
   nie poprawka); `MAX_PATH` 260; czy `gix-config` widzi `%PROGRAMDATA%\Git\config`;
   buildy `musl`; zachowanie pod rootem w kontenerze CI.
