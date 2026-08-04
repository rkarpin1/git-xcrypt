# Opis

Aplikacja ma szyfrować wskazane pliki i całe katalogi w zdalnym repozytorium git.
Jest to ważne, gdyż istnieją pliki lub całe katalogi zawierające sekrety i nie chcemy, aby były prezentowane w np. GitHub.

Tworzony jest nowy projekt ze względów edukacyjnych oraz dlatego, że projekty bazowe nie są rozwijane, a mam kolejne pomysły na rozwój.

**Relacja do projektów bazowych:** projekt jest *inspirowany* [AGWA/git-crypt](https://github.com/AGWA/git-crypt) i [AprilNEA/git-crypt-rs](https://github.com/AprilNEA/git-crypt-rs), ale **nie jest ich portem 1:1**. Zgodne pozostają: nazewnictwo komend, model pracy (clean/smudge, lock/unlock) i ogólne UX. Format zaszyfrowanego pliku, format klucza oraz sposób zarządzania odbiorcami są **własne** (patrz „Kryptografia i format pliku"). Repozytorium zaszyfrowane oryginalnym `git-crypt` **nie** będzie obsługiwane.

# Słownik pojęć

- **clean filter** — proces uruchamiany przez git przy dodawaniu pliku do indeksu; u nas: szyfruje. Czyta plaintext ze `stdin`, pisze ciphertext na `stdout`.
- **smudge filter** — proces uruchamiany przy wypisywaniu pliku do katalogu roboczego; u nas: deszyfruje.
- **diff filter** — pozwala `git diff` pokazywać różnice na odszyfrowanej treści.
- **lock** — usunięcie klucza z lokalnego repo i zamiana plików roboczych na zaszyfrowane.
- **unlock** — wczytanie klucza i odszyfrowanie plików roboczych.
- **odbiorca (recipient)** — osoba mogąca odszyfrować klucz repozytorium przy pomocy własnego klucza prywatnego.

# Założenia funkcjonalne

- W katalogu roboczym użytkownika pliki są **odszyfrowane**; w repozytorium zdalnym (GitHub) te same pliki są **zaszyfrowane**.
- Inicjacja projektu ma być prosta — wystarcza `git-xcrypt init`. Nie powstają żadne dodatkowe skrypty pomocnicze ani pliki, których użytkownik musi pilnować ręcznie.
- Wymagany klucz repozytorium jest generowany automatycznie przy inicjacji.
- Konfiguracja plików i katalogów do szyfrowania opiera się na **własnym pliku konfiguracyjnym o składni podobnej do `.gitignore`**, nazwanym `.git-xcrypt`. Jest to świadome odejście od oryginału, który wymaga ręcznej edycji `.gitattributes`.
  - Plik `.git-xcrypt` jest wersjonowany w repozytorium.
  - Aplikacja generuje z niego wpisy w `.gitattributes` (git nie potrafi czytać naszego formatu bezpośrednio) — wygenerowana sekcja jest oznaczona markerami i **zarządzana wyłącznie przez narzędzie**.
  - Wzorzec katalogowy `sekrety/` musi zostać przetłumaczony na działający w git wzorzec `sekrety/**` — obsługa tego przypadku jest wymogiem, nie detalem.
  - Negacje (`!plik`) muszą być obsłużone lub jawnie odrzucone z czytelnym błędem.
- Pozostałe komendy `git-xcrypt` mają odpowiadać projektom źródłowym co do nazwy i zachowania, ale każda wymaga oddzielnej dyskusji i potwierdzenia przed implementacją.

# Zakres MVP / poza zakresem

**W zakresie v0.1:**

- `git-xcrypt init` — generuje klucz repozytorium, rejestruje filtry w `.git/config`, tworzy `.git-xcrypt` (jeśli brak) i synchronizuje `.gitattributes`.
- `git-xcrypt status` — wypisuje, które pliki są szyfrowane, a które **powinny być, a nie są** (np. zacommitowane przed konfiguracją).
- `git-xcrypt lock` — usuwa klucz z repo i zaszyfrowuje pliki w katalogu roboczym.
- `git-xcrypt unlock` — wczytuje klucz i odszyfrowuje pliki w katalogu roboczym.
- `git-xcrypt export-key` / `import-key` — eksport i import klucza symetrycznego do przenoszenia między maszynami.
- `git-xcrypt sync` — regeneruje sekcję w `.gitattributes` na podstawie `.git-xcrypt`.
- `git-xcrypt add-user` / `list-users` — zarządzanie odbiorcami (patrz „Zarządzanie kluczami i użytkownikami").

**Poza zakresem v0.1** (do świadomego odłożenia, nie do cichego pominięcia):

- Wsparcie dla zewnętrznego `gpg` i keyringu OpenPGP użytkownika.
- Wiele niezależnych kluczy w jednym repo (`--key-name`).
- Migracja repozytoriów zaszyfrowanych oryginalnym `git-crypt`.
- Rotacja klucza i wycofywanie dostępu odbiorcy z przepisaniem historii.

# Założenia techniczne

- Aplikacja napisana w Rust, działa na Windows, macOS i Linux.
- Edycja Rust 2024; MSRV ustalony i utrzymywany w CI (edycja 2024 wymaga min. Rust 1.85).
- Struktura: `lib` (logika, testowalna) + cienki `bin` (parsowanie argumentów, kody wyjścia).
- Obsługa błędów: `thiserror` w bibliotece, czytelne komunikaty w binarce. Brak `unwrap()`/`panic!` na ścieżkach obsługujących dane wejściowe.
- **Zero `unsafe`** w kodzie własnym, szczególnie w warstwie kryptograficznej. Kryptografia wyłącznie z audytowanych bibliotek (RustCrypto), nigdy implementowana samodzielnie.
- Instalacja przez `cargo install`.
- Pliki wykonywalne budowane w GitHub Actions dla każdej platformy — powstają binaria dla Windows, macOS (x86_64 + aarch64) i Linux.
- Binaria muszą być samowystarczalne: bez wymaganych bibliotek zewnętrznych i bez wywoływania zewnętrznych procesów (w tym `gpg`). Linux: preferowany target `musl` dla statycznego linkowania.
- Możliwa instalacja standardowymi narzędziami każdej z platform (brew itp.).

# Kryptografia i format pliku

**Wymóg nadrzędny — determinizm.** Ten sam plaintext z tym samym kluczem musi dawać **bajt w bajt ten sam ciphertext**. Bez tego git przy każdym `status` widziałby zmiany w niezmienionych plikach, a każdy commit generowałby fałszywe różnice. To wyklucza losowy nonce.

Przyjęte rozwiązanie:

- Szyfr: **AES-256-SIV** (RFC 5297, crate `aes-siv`) — deterministyczny AEAD. Syntetyczny IV wyliczany z treści, więc determinizm jest własnością konstrukcji, a nie obejściem. Alternatywa do rozważenia: XChaCha20-Poly1305 z nonce = keyed BLAKE3 z plaintextu.
- Nagłówek pliku: własny magic (np. `\0GITCRYPTRS\0`), wersja formatu (1 bajt), identyfikator klucza, znacznik AEAD. Wersja formatu jest **obowiązkowa od pierwszego wydania** — pozwala później zmienić szyfr bez psucia istniejących repo.
- Plik nierozpoznany po nagłówku → czytelny błąd, nigdy ciche przepuszczenie treści.
- Deszyfrowanie weryfikuje tag AEAD; niepowodzenie to błąd, nie ostrzeżenie.
- Duże pliki: przetwarzanie strumieniowe tam, gdzie to możliwe. Uwaga: SIV wymaga dwóch przebiegów po danych — dla plików ponad ustalony próg konieczne buforowanie na dysku zamiast w RAM.
- Pliki puste i binarne muszą być obsłużone poprawnie (pusty plik również szyfrowany).

# Zarządzanie kluczami i użytkownikami

- Klucz repozytorium leży w `.git/git-xcrypt/keys/` — **nigdy** nie jest commitowany. Katalog `.git/` nie podlega wersjonowaniu, ale aplikacja dodatkowo pilnuje, by klucz nie trafił do drzewa roboczego.
- Uprawnienia pliku klucza: `0600` na systemach uniksowych; na Windows odpowiednie ACL ograniczone do właściciela.
- Klucz nigdy nie jest wypisywany na `stdout` poza jawną komendą `export-key`.
- **Odbiorcy natywnie w Rust, bez zewnętrznego `gpg`.** Rekomendacja: format **age** (crate `age`, odbiorcy X25519, opcjonalnie passphrase przez scrypt) — mały, nowoczesny, w pełni rustowy, nie ciągnie zależności systemowych. Sequoia (OpenPGP) daje zgodność z istniejącymi kluczami GPG kosztem znacznie większego nakładu i rozmiaru binarki. **Wybór do potwierdzenia** — patrz „Otwarte decyzje".
- Klucz repozytorium jest zaszyfrowany osobno dla każdego odbiorcy; koperty przechowywane w repozytorium w katalogu `.git-xcrypt-keys/`, więc każdy uprawniony może wykonać `unlock` po sklonowaniu. Katalog **nie** może nazywać się `.git-xcrypt/` — tę nazwę zajmuje plik konfiguracyjny, a plik i katalog o tej samej nazwie nie mogą współistnieć.
- Dodanie odbiorcy daje mu dostęp do **całej historii**, nie tylko do commitów od momentu dodania — klucz repozytorium jest jeden i niezmienny. Analogicznie usunięcie odbiorcy nie odbiera dostępu do tego, co już sklonował; wymaga rotacji klucza. Obie własności muszą być jasno opisane w dokumentacji użytkownika.

# Integracja z git

- Mechanizm: filtry `clean` / `smudge` / `diff` zarejestrowane w `.git/config`, aktywowane wpisami `filter=git-xcrypt diff=git-xcrypt` w `.gitattributes`.
- **Twarda reguła: na ścieżce clean/smudge nic poza danymi nie może trafić na `stdout`.** Żadnych `println!`, logów, pasków postępu. Diagnostyka wyłącznie na `stderr`. Naruszenie tej reguły cicho uszkadza pliki użytkownika.
- Filtr musi być odporny na wielokrotne uruchomienie: szyfrowanie już zaszyfrowanej treści i deszyfrowanie plaintextu to przypadki do wykrycia i obsłużenia (idempotencja po nagłówku).
- Kody wyjścia: `0` sukces, niezerowe kody rozróżniające „brak klucza", „zły format", „błąd konfiguracji".
- **Twarda reguła: filtr rejestrujemy z `filter.git-xcrypt.required = true`.** Wbrew intuicji sam niezerowy kod filtra **nie** przerywa operacji gita. Zmierzone na git 2.55 (repozytorium tymczasowe, nie na tym projekcie): bez tej flagi filtr `clean` kończący się kodem `3` daje `git add` **kod wyjścia 0**, git traktuje awarię jako nieszkodliwą i przepuszcza treść bez zmian — do indeksu i do bazy obiektów trafia **plaintext**, a użytkownik widzi tylko `error:` w szumie i udany commit. Z flagą: `fatal: <plik>: clean filter 'git-xcrypt' failed`, plik nie wchodzi do indeksu, żaden obiekt nie powstaje. Zabezpieczenie „błąd przerywa operację" jest więc własnością tej flagi, a nie samego gita — jej ustawienie należy do `init` i jest warunkiem gwarantki z PRD §Guardrails, nie detalem konfiguracji. Regresji pilnują dwa testy w `tests/filter_edge_cases.rs`; usunięcie flagi z harnessu wywala oba.
- `.gitattributes` dla plików szyfrowanych musi zawierać `-text`, żeby `core.autocrlf` na Windows nie modyfikował ciphertextu — patrz „Końce linii (LF/CRLF)", gdzie opisany jest zmierzony mechanizm i jego konsekwencje.
- Znane ograniczenia do udokumentowania: `git archive` eksportuje treść zaszyfrowaną (filtry nie są stosowane); submoduły mają własną konfigurację i wymagają osobnej inicjacji.

# Końce linii (LF/CRLF)

Ustalenia z 2026-08-04, oparte na pomiarach na git 2.55 (repozytorium tymczasowe, nie na tym projekcie).

**Kolejność, w jakiej git składa filtr z konwersją EOL** — to jest fakt, na którym wisi cała reszta:

- checkin: katalog roboczy → **clean** → `CRLF→LF` → blob
- checkout: blob → `LF→CRLF` → **smudge** → katalog roboczy

Filtr zawsze widzi bajty od strony katalogu roboczego, a git swoją konwersję wykonuje **na wyniku filtra**, czyli na ciphertexcie. Wniosek: git nie może przeprowadzić konwersji dla plików szyfrowanych w żadnym ustawieniu — zawsze trafiłby w ciphertext, nie w plaintext. Dlatego `-text` na ścieżkach szyfrowanych jest wymogiem, a nie ostrożnością.

**`-text` wygrywa z `eol`.** Zmierzone: blob trzymający CRLF, `core.autocrlf=true`, atrybut `-text eol=lf` → w katalogu roboczym nadal CRLF, git nie zmienia ani bajta. Skoro na naszych ścieżkach wymuszamy `-text`, użytkownik **nie ma sposobu**, żeby środkami gita oznaczyć plik szyfrowany jako „tylko LF" — atrybut `eol=lf`, którym repozytoria trzymają np. skrypty powłoki, jest niedostępny dokładnie na tych plikach, na których byłby potrzebny.

**Konwersję przejmuje git-xcrypt, ale asymetrycznie:**

- **clean (przed szyfrowaniem) nie czyta konfiguracji gita.** Zawsze `CRLF→LF` dla plików zadeklarowanych jako tekst, identycznie na każdej maszynie. Gdyby czytał `core.autocrlf`, ten sam plik dałby na Windows inny plaintext niż na Linuksie, więc inny ciphertext, więc inny blob — i determinizm pada.
- **smudge (po odszyfrowaniu) czyta konfigurację gita.** To jedyny moment, w którym różnice między maszynami są dozwolone i pożądane. Potrzebne klucze: `core.autocrlf`, `core.eol`, plus platforma dla wartości `native`.

Reguła do odtworzenia na wyjściu smudge (zmierzona, przy ustawionym `text`):

| `core.autocrlf` | `core.eol` | wynik w katalogu roboczym          |
| --------------- | ---------- | ---------------------------------- |
| `true`          | dowolne    | CRLF (`core.eol` ignorowany)       |
| `input`         | dowolne    | LF (`core.eol` ignorowany)         |
| `false`         | `crlf`     | CRLF                               |
| `false`         | `lf`       | LF                                 |
| `false`         | `native`   | platforma (LF/macOS, CRLF/Windows) |

Niezmiennik, który spina asymetrię: na Windows z `autocrlf=true` smudge zapisuje CRLF, w katalogu roboczym leży CRLF, a następny clean normalizuje z powrotem do LF → ten sam ciphertext co przed checkoutem → `git status` czysty. To ten sam model, którym git obsługuje indeks, przesunięty o jeden krok, przed AEAD.

**Deklaracja trybu należy do `.git-xcrypt`, nie do gita.** Skoro `-text` odbiera użytkownikowi atrybuty `text`/`eol` na plikach szyfrowanych, `.git-xcrypt` musi przejąć tę samą semantykę per wzorzec: `text`, `-text`, `eol=lf`, `eol=crlf` oraz zachowanie domyślne przy braku deklaracji. Nie wymyślamy własnego modelu — odtwarzamy ten, który użytkownik zna z `.gitattributes`, z tą różnicą, że `eol=*` działa u nas na wyjściu smudge, a nie w gicie. Deklaracja jest wersjonowana, więc jest jednakowa na wszystkich maszynach — i to jest warunek, pod którym powyższy niezmiennik trzyma.

**Konfigurację czytamy biblioteką, nie procesem potomnym.** `gix-config` (gitoxide) daje pełną precedencję system/global/repo/worktree wraz z `include`/`includeIf`, kompiluje się do środka binarki i nie łamie wymogu samowystarczalności z „Założeń technicznych". Wywoływanie `git config` odpada: git uruchamia nowy proces filtra na każdy plik, więc byłoby to N spawnów na ścieżce gorącej, najdroższych akurat na Windows. Pozostaje jedna binarka `git-xcrypt` w kilku trybach (`clean`, `smudge`, `diff` rejestrowane przez `init`; reszta wywoływana przez użytkownika); żadnego osobnego programu pomocniczego ani demona.

**Świadomie przyjęte ograniczenie:** plik o mieszanych końcach linii nie przetrwa round-tripu — normalizacja jest stratna, więc po `unlock` taki plik wróci inny niż był i `git status` pokaże zmianę. Git broni się przed tym przez `core.safecrlf`; czy odtwarzamy to ostrzeżenie, jest otwarte.

# Bezpieczeństwo i świadome ograniczenia

Wszystkie poniższe są **akceptowanymi kompromisami** konstrukcji, nie błędami:

- Wyciekają **metadane**: nazwy plików, ścieżki, rozmiary (z dokładnością do narzutu formatu), daty commitów i fakt, że plik się zmienił.
- Szyfrowanie deterministyczne ujawnia, że dwa pliki mają identyczną treść, oraz że plik wrócił do poprzedniej wersji.
- **Największe realne ryzyko: sekret zacommitowany zanim wzorzec trafił do konfiguracji.** Zostaje w historii w postaci jawnej na zawsze. Przeciwdziałanie: `git-xcrypt status` wskazuje takie pliki, a dokumentacja opisuje procedurę czyszczenia historii i rotacji sekretu.
- Klucz w `.git/` jest tak bezpieczny jak dysk i konto użytkownika — narzędzie nie chroni przed skompromitowaną maszyną.
- Poza modelem zagrożeń: atakujący z dostępem do odszyfrowanego katalogu roboczego, ataki side-channel, ochrona przed samym hostingiem po `unlock` na CI.
- Sekrety nigdy nie trafiają do repozytorium projektu — również w testach i przykładach.

# Dystrybucja, licencja i nazewnictwo

- **Licencja do rozstrzygnięcia przed pierwszym publicznym wydaniem.** AGWA/git-crypt jest na GPL-3.0. Skoro nie kopiujemy kodu ani formatu, praca pochodna prawdopodobnie nie zachodzi, ale należy to potwierdzić — również dla `git-crypt-rs`, którego licencję trzeba sprawdzić. Do czasu rozstrzygnięcia repozytorium pozostaje prywatne albo oznaczone jako GPL-3.0.
- Atrybucja projektów inspirujących w README niezależnie od wyniku analizy licencyjnej.
- **Kolizja nazw — rozstrzygnięte 2026-08-04: crate i binarka nazywają się `git-xcrypt`.** Sprawdzone przed decyzją: `git-crypt` na crates.io jest **zajęte** przez `AprilNEA/git-crypt-rs` (0.1.4, ostatnia aktualizacja 2025-11-15), a binarki `git-crypt` i `git-secret` mają formuły w Homebrew — plik wykonywalny o którejkolwiek z tych nazw byłby po cichu przesłaniany na `PATH` przez wcześniejszy wpis. `git-xcrypt` jest wolne na crates.io, nie ma formuły w Homebrew i nie znaleziono kolidującego projektu. Nazwa zachowuje mechanizm podkomendy: binarka `git-xcrypt` na `PATH` daje `git xcrypt <komenda>`.
- Homebrew wymaga własnego tapa (do core trafiają tylko projekty z ustaloną popularnością).
- Wydania z GitHub Actions: podpisane artefakty, sumy kontrolne SHA-256, spójne wersjonowanie tagu i `Cargo.toml`.

# Jakość i testy

- Testy integracyjne na **prawdziwych repozytoriach git** w katalogu tymczasowym: init → dodanie sekretu → commit → sprawdzenie, że blob w obiekcie gita jest zaszyfrowany → clone → unlock → porównanie treści.
- Testy właściwości: `decrypt(encrypt(x)) == x` oraz `encrypt(x) == encrypt(x)` (determinizm).
- Wektory testowe formatu zamrożone w repo — chronią przed przypadkową zmianą formatu psującą istniejące repozytoria.
- CI na wszystkich trzech platformach: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo audit`.
- Scenariusz regresyjny na Windows z włączonym `core.autocrlf=true`.

# Kryteria akceptacji

Projekt uznajemy za działający, gdy poniższy scenariusz przechodzi automatycznie na trzech platformach:

1. `git init` + `git-xcrypt init` w nowym repo.
2. Dodanie do `.git-xcrypt` wpisów `sekrety/` i `*.env`.
3. Commit pliku `sekrety/haslo.txt` i `.env`, push do zdalnego repo.
4. Zawartość blobów w zdalnym repo jest zaszyfrowana; `.git-xcrypt` i `.gitattributes` pozostają jawne.
5. `git clone` na drugiej maszynie pokazuje pliki zaszyfrowane; po `git-xcrypt unlock` treść jest identyczna z oryginałem.
6. Powtórny `git status` po unlock jest czysty (dowód determinizmu).

# Otwarte decyzje

1. **Format odbiorców: age czy OpenPGP (sequoia)?** Rekomendacja: age dla v0.1.
2. ~~**Nazwa crate'a i binarki** wobec kolizji z oryginalnym `git-crypt`.~~ Rozstrzygnięte 2026-08-04: `git-xcrypt` dla obu — patrz „Dystrybucja, licencja i nazewnictwo".
3. **Licencja projektu** po weryfikacji licencji projektów inspirujących.
4. ~~Nazwa pliku konfiguracyjnego.~~ Rozstrzygnięte 2026-08-04: plik nazywa się `.git-xcrypt`, a koperty kluczy — gdyby kiedykolwiek powstały — trafiają do `.git-xcrypt-keys/`. To usuwa kolizję, która była istotą tego pytania: plik i katalog o identycznej nazwie nie mogą współistnieć.
5. Próg rozmiaru pliku, powyżej którego przechodzimy na buforowanie dyskowe zamiast RAM.
6. Które komendy z oryginału poza listą MVP faktycznie chcemy odtworzyć.
7. **Zachowanie domyślne przy braku deklaracji EOL w `.git-xcrypt`**: traktować plik jako binarny (żadnej konwersji, bezpieczne) czy jako `text=auto` z heurystyką gita (NUL w pierwszych 8000 bajtach)? Heurystyka nie łamie determinizmu — ta sama treść daje tę samą decyzję — ale jest cicha: dopisanie bajtu zerowego przełącza tryb i zmienia cały ciphertext. Patrz „Końce linii (LF/CRLF)".
8. **Czy odtwarzamy ostrzeżenie `core.safecrlf`** dla plików o mieszanych końcach linii, które nie przetrwają round-tripu.
