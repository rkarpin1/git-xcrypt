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

**Poza zakresem v0.1** (do świadomego odłożenia, nie do cichego pominięcia):

- **Zarządzanie odbiorcami (`add-user` / `list-users`, koperty kluczy) oraz klucze per użytkownik i per stanowisko.** Rozstrzygnięte 2026-08-04 zgodnie z `prd.md` §Non-Goals — wcześniej ten dokument wymieniał je w zakresie v0.1, co było sprzecznością z PRD. Model v0.1 jest jednoosobowy, klucz przenosi się plikiem. Format pliku zaszyfrowanego jest na to gotowy: koperty pakują klucz główny i nie dotykają szyfrowania treści (patrz „Zarządzanie kluczami").
- Wsparcie dla zewnętrznego `gpg` i keyringu OpenPGP użytkownika.
- Wiele niezależnych kluczy w jednym repo (`--key-name`).
- Migracja repozytoriów zaszyfrowanych oryginalnym `git-crypt`.
- Rotacja klucza i wycofywanie dostępu odbiorcy z przepisaniem historii.

# Założenia techniczne

- Aplikacja napisana w Rust, działa na Windows, macOS i Linux.
- Edycja Rust 2024; MSRV ustalony i utrzymywany w CI (edycja 2024 wymaga min. Rust 1.85).
- Struktura: `lib` (logika, testowalna) + cienki `bin` (parsowanie argumentów, kody wyjścia).
- Obsługa błędów: `thiserror` w bibliotece, czytelne komunikaty w binarce. Brak `unwrap()`/`panic!` na ścieżkach obsługujących dane wejściowe.
- **Zero `unsafe`** w kodzie własnym, szczególnie w warstwie kryptograficznej. Kryptografia **wyłącznie z crate'ów RustCrypto**, nigdy implementowana samodzielnie — nie piszemy prymitywów ani nie składamy własnych konstrukcji z prymitywów. Sformułowanie „wyłącznie z audytowanych bibliotek" byłoby nieprawdziwe: audyt NCC Group z 2020 objął `aes-gcm` i `chacha20poly1305`, natomiast wybrany `aes-siv` audytu **nie ma** i jest to świadomie przyjęte ryzyko — uzasadnienie w „Kryptografia i format pliku".
- Instalacja przez `cargo install`.
- Pliki wykonywalne budowane w GitHub Actions dla każdej platformy — powstają binaria dla Windows, macOS (x86_64 + aarch64) i Linux.
- Binaria muszą być samowystarczalne: bez wymaganych bibliotek zewnętrznych i bez wywoływania zewnętrznych procesów (w tym `gpg`). Linux: preferowany target `musl` dla statycznego linkowania.
- Możliwa instalacja standardowymi narzędziami każdej z platform (brew itp.).

# Kryptografia i format pliku

**Wymóg nadrzędny — determinizm.** Ten sam plaintext z tym samym kluczem musi dawać **bajt w bajt ten sam ciphertext**. Bez tego git przy każdym `status` widziałby zmiany w niezmienionych plikach, a każdy commit generowałby fałszywe różnice. To wyklucza losowy nonce.

## Szyfr — rozstrzygnięte 2026-08-04

**AES-256-SIV (RFC 5297), crate `aes-siv`.** Deterministyczny AEAD (DAE): syntetyczny IV liczony z treści przez S2V/CMAC, więc determinizm jest **trybem zamierzonym i objętym dowodem**, a nie obejściem ani trybem degradacji. Klucz 64 B (dwie połówki: S2V i CTR), syntetyczny IV 16 B.

Sprawdzone przed decyzją (crates.io i RustSec advisory-db, 2026-08-04):

- W czystym Ruście istnieją **dokładnie dwa** deterministyczne AEAD i oba pochodzą z tego samego repozytorium RustCrypto/AEADs: `aes-siv` (RFC 5297) i `aes-gcm-siv` (RFC 8452). Trzeciej implementacji nie ma; `miscreant` jest porzucony.
- `aes-siv` nie ma żadnego wpisu w RustSec.
- Ostatnia stabilna `aes-siv` to 0.7.0 z 2022-07-30, przy `0.8.0-rc.3` w drodze. To **nie jest** blokada: RFC 5297 jest zamrożone, więc wersja crate'a nie wchodzi do formatu — wyjście dla danego klucza i plaintextu jest identyczne w 0.7 i 0.8, a bump będzie zmianą jednej linii w `Cargo.toml`. `master` tego repozytorium deklaruje MSRV 1.85, jak reszta rodziny.

Odrzucone warianty i powody:

| Wariant | Powód odrzucenia |
| --- | --- |
| AES-GCM ze stałym nonce | forbidden attack (Joux) — powtórzony nonce ujawnia klucz GHASH i pozwala fałszować **dowolne** wiadomości pod tym kluczem |
| AES-GCM z nonce wyprowadzonym z plaintextu | nasza kompozycja, a do tego nonce 96-bitowy zamiast 128-bitowego SIV — kolizja dla dwóch różnych plaintextów wraca do przypadku katastrofalnego |
| XChaCha20-Poly1305 z nonce wyprowadzonym z plaintextu | najmocniejsza alternatywa (nonce 192-bitowy, crate audytowany i świeży), ale **konstrukcję składamy my** — kilkanaście linii, w których błąd jest cichy. Wymagałby też `blake3` lub `hkdf` do wyprowadzenia; przy kryterium „tylko RustCrypto" BLAKE3 odpada |
| AES-GCM-SIV (RFC 8452) | **nie odrzucone — zapasowa opcja pod `suite = 0x02`.** Odporny na nadużycie nonce, więc stały nonce ujawnia wyłącznie równość plaintextów (kompromis już akceptowany). Słabszy argumentacyjnie: determinizm jest tu trybem degradacji, IV ma 96 bitów, a kadencja wydań jest ta sama co `aes-siv` |
| `aws-lc-rs` (ma `AES_256_GCM_SIV`) | kod C budowany przez cmake — wywraca czysty Rust, statyczny musl i regułę zero `unsafe` |
| `ring`, `openssl`, `boring`, `orion`, `dryoc` | brak SIV albo zależność systemowa / build C |
| własna implementacja RFC 5297 z `aes` + `cmac` | wyklucza reguła „nigdy nie implementujemy prymitywów" |

**Świadomie przyjęte ryzyko:** `aes-siv` **nie był audytowany**. Audyt NCC Group z 2020 (zlecony przez MobileCoin) objął `aes-gcm` i `chacha20poly1305` — nie objął żadnego z dwóch crate'ów SIV. Nie jest to wybór między audytowanym a nieaudytowanym: **żaden deterministyczny AEAD w Ruście audytu nie ma**, więc kryterium audytu wypada z równania po obu stronach i zostaje jakość konstrukcji. Rekompensata: zamrożone wektory z RFC 5297 Appendix A w testach (patrz „Jakość i testy"). Rdzeń AES, na którym stoi S2V, pochodzi z crate `aes`, który NCC przejrzało w ramach przeglądu AES/GCM — nieaudytowana jest nadbudowa SIV, nie sam AES.

## Format pliku zaszyfrowanego

```
offset  dł.  pole                                          status
     0   11  magic  \x00GITXCRYPT\x00                      zamrożone na zawsze
    11    1  format_version = 0x01                         zamrożone na zawsze
    12    1  suite = 0x01 (AES-256-SIV)                    zamrożone na zawsze
    13    1  flags — bit 0: plaintext znormalizowany do LF zamrożone na zawsze
    14    8  key_id                                        zamrożone na zawsze
    22   16  syntetyczny IV                                definiuje suite
    38   ..  ciphertext                                    definiuje suite
```

- **Bajty `0..22` idą do AES-SIV jako associated data.** Wersja, suite, flagi i `key_id` są uwierzytelnione — przestawienie któregokolwiek unieważnia tag zamiast po cichu zmienić interpretację pliku.
- **Reguła rozszerzalności: bajty `0..22` są zamrożone na zawsze, a wszystko od offsetu 22 definiuje `suite`.** Parser czyta stały prefiks, rozpoznaje suite i dopiero wtedy wie, jak czytać resztę. Dzięki temu tryb blokowy dla wielkich plików, kompresja przed szyfrowaniem czy dopełnianie rozmiaru mieszczą się w nowym `suite` — bez zmiany `format_version` i bez psucia istniejących plików.
- **`flags`:** bit 0 mówi, czy plaintext został znormalizowany do LF przy szyfrowaniu. Pozostałe 7 bitów jest zarezerwowane, musi być zerowe, a plik z ustawionym nieznanym bitem jest **odrzucany** (fail closed) — starsza binarka nie udaje, że rozumie nowszy plik. Uzasadnienie bitu 0: patrz „Końce linii".
- **`key_id`** identyfikuje **klucz główny**, nie szyfr — zostaje stabilny przy zmianie suite. Daje komunikat „zaszyfrowane innym kluczem" zamiast gołej porażki tagu i jest tym, co umożliwia rotację klucza oraz wiele kluczy w jednym repozytorium bez zmiany formatu.
- **Narzut stały 38 bajtów.** SIV szyfruje trybem CTR, więc długość ciphertextu równa się długości plaintextu: `rozmiar pliku = 38 + rozmiar treści`, co do bajta. Rozmiar przecieka dokładnie — to jest wyciek metadanych akceptowany w „Bezpieczeństwo i świadome ograniczenia".
- **Pusty plik daje 38 bajtów** (sam nagłówek i IV) — obsłużony bez przypadku szczególnego.
- **Wiodący NUL** sprawia, że git i inne narzędzia rozpoznają plik jako binarny (heurystyka NUL w pierwszych 8000 bajtach), więc `git diff` bez klucza pokaże `Binary files differ` zamiast szumu.
- Plik nierozpoznany po nagłówku → czytelny błąd, nigdy ciche przepuszczenie treści.
- Deszyfrowanie weryfikuje tag AEAD; niepowodzenie to błąd, nie ostrzeżenie. Używamy API jednorazowego, **nigdy `*_detached`** — RUSTSEC-2023-0096 dotyczył dokładnie tego, że `aes-gcm::decrypt_in_place_detached` wydawał plaintext mimo porażki weryfikacji tagu.
- **Świadome ograniczenie:** plik jawny zaczynający się dokładnie od 11 bajtów magic zostanie wzięty za zaszyfrowany. Przy wiodącym NUL nierealne dla tekstu, pomijalne dla binariów.
- Duże pliki: `aes-siv` 0.7 ma API jednorazowe, więc dziś plik trafia do RAM w całości. SIV wymaga dwóch przebiegów po danych — powyżej ustalonego progu konieczne buforowanie na dysku albo nowy `suite` z trybem blokowym. Patrz „Otwarte decyzje".

## Idempotencja po nagłówku

| Ścieżka | Wejście | Zachowanie |
| --- | --- | --- |
| clean | brak magic | szyfruj — **nigdy nie przepuszczaj plaintextu** |
| clean | magic + nasz `key_id` + tag OK | przepuść bez zmian; z determinizmu jest to bajt w bajt to, co dałoby ponowne szyfrowanie |
| clean | magic + obcy `key_id` albo zły tag | błąd, przerwanie operacji |
| smudge | magic | odszyfruj; porażka tagu to błąd, nie ostrzeżenie |
| smudge | brak magic | przepuść bez zmian + ostrzeżenie na `stderr` |

Ostatni wiersz jest konieczny: to plik zacommitowany, **zanim** wzorzec trafił do konfiguracji. Odmowa uniemożliwiłaby checkout starej historii. Nie łamie to reguły „nigdy nie przepuszczaj po cichu" — plaintext w katalogu roboczym jest tam, gdzie ma być, a ostrzeżenie idzie na `stderr`. Kierunek odwrotny (clean) przepuszczać nie wolno.

## Przyszłe funkcjonalności wobec tego formatu

Sprawdzone 2026-08-04 przed zamrożeniem. Bez zmian w formacie obsługują się: odbiorcy per użytkownik i per stanowisko, klucze sprzętowe, migracja post-kwantowa (wszystko na poziomie kopert), rotacja klucza i wiele kluczy w repo (`key_id`), plik klucza chroniony hasłem (własny nagłówek pliku klucza), zmiana szyfru i komenda `migrate` (`suite`, `format_version`), audyt „którym kluczem zaszyfrowano" (`key_id`). Przez nowy `suite` mieszczą się: tryb blokowy dla wielkich plików, kompresja przed szyfrowaniem, dopełnianie rozmiaru, klucz wyprowadzany per ścieżka oraz wiązanie ciphertextu ze ścieżką przez AAD (koszt tego ostatniego: `git mv` przepisuje blob, więc git traci wykrywanie zmian nazw — dlatego w `suite = 0x01` ścieżki w AAD **nie ma**). Poza zasięgiem formatu pozostaje ukrywanie nazw plików i ścieżek — to nie jest własność pojedynczego pliku i jest w PRD §Non-Goals.

# Zarządzanie kluczami i użytkownikami

**Dwa poziomy klucza — rozstrzygnięte 2026-08-04.** Plik klucza trzyma **klucz główny 32 B** z CSPRNG, a nie klucz szyfru. Klucz dla konkretnego suite wyprowadzamy z niego przez HKDF-SHA-256 (crate'y `hkdf` + `sha2`, oba RustCrypto):

```
klucz główny  = 32 B z CSPRNG                       ← to leży w .git/git-xcrypt/keys/
klucz suite   = HKDF-SHA-256(ikm = klucz główny,
                             info = "git-xcrypt suite 0x01 aes-256-siv",
                             len  = 64)
key_id        = HKDF-SHA-256(ikm = klucz główny,
                             info = "git-xcrypt key-id v1")[0..8]
```

Powód jest zaporowy: różne szyfry biorą klucze różnej długości (AES-256-SIV 64 B, AES-256-GCM-SIV i XChaCha20 po 32 B), a format pliku klucza jest zamrożony **tak samo mocno** jak format danych, bo leży u użytkowników i w kopiach zapasowych. Przy kluczu głównym każdy przyszły suite dostaje własny materiał z separacją domen, format pliku klucza nie zmienia się nigdy, a `key_id` identyfikuje klucz niezależnie od szyfru — więc `export-key`, `import-key` i `unlock` są odporne na zmianę suite. Plik klucza ma własny nagłówek z wersją, z tego samego powodu co plik danych.

- Klucz repozytorium leży w `.git/git-xcrypt/keys/` — **nigdy** nie jest commitowany. Katalog `.git/` nie podlega wersjonowaniu, ale aplikacja dodatkowo pilnuje, by klucz nie trafił do drzewa roboczego.
- Uprawnienia pliku klucza: `0600` na systemach uniksowych; na Windows odpowiednie ACL ograniczone do właściciela.
- Klucz nigdy nie jest wypisywany na `stdout` poza jawną komendą `export-key`.
- **Odbiorcy natywnie w Rust, bez zewnętrznego `gpg`** — poza zakresem v0.1, patrz „Zakres MVP". Gdy wejdą: koperta pakuje **klucz główny 32 B**, więc jest niezależna zarówno od wybranego szyfru, jak i od formatu pliku danych; dodanie odbiorców nie wymaga żadnej zmiany w formacie zaszyfrowanego pliku. Kandydat: format **age** (crate `age`, odbiorcy X25519) — mały, nowoczesny, bez zależności systemowych, ale **spoza RustCrypto**, co koliduje z regułą z „Założeń technicznych". Odpowiednikiem wewnątrz RustCrypto byłby `crypto_box` (X25519 + XSalsa20-Poly1305) kosztem własnego, nieinteroperacyjnego formatu koperty. Sequoia (OpenPGP) daje zgodność z kluczami GPG kosztem znacznie większego nakładu i rozmiaru binarki. **Rozstrzygnięcie odłożone do momentu, w którym odbiorcy wejdą do zakresu** — patrz „Otwarte decyzje".
- Klucz repozytorium jest zaszyfrowany osobno dla każdego odbiorcy; koperty przechowywane w repozytorium w katalogu `.git-xcrypt-keys/`, więc każdy uprawniony może wykonać `unlock` po sklonowaniu. Katalog **nie** może nazywać się `.git-xcrypt/` — tę nazwę zajmuje plik konfiguracyjny, a plik i katalog o tej samej nazwie nie mogą współistnieć.
- Dodanie odbiorcy daje mu dostęp do **całej historii**, nie tylko do commitów od momentu dodania — klucz repozytorium jest jeden i niezmienny. Analogicznie usunięcie odbiorcy nie odbiera dostępu do tego, co już sklonował; wymaga rotacji klucza. Obie własności muszą być jasno opisane w dokumentacji użytkownika.

# Integracja z git

- Mechanizm: filtry `clean` / `smudge` / `diff` zarejestrowane w `.git/config`, aktywowane wpisami `filter=git-xcrypt diff=git-xcrypt` w `.gitattributes`.
- **Twarda reguła: na ścieżce clean/smudge nic poza danymi nie może trafić na `stdout`.** Żadnych `println!`, logów, pasków postępu. Diagnostyka wyłącznie na `stderr`. Naruszenie tej reguły cicho uszkadza pliki użytkownika.
- Filtr musi być odporny na wielokrotne uruchomienie: szyfrowanie już zaszyfrowanej treści i deszyfrowanie plaintextu to przypadki do wykrycia i obsłużenia — tabela zachowań w „Kryptografia i format pliku" → „Idempotencja po nagłówku".
- **Kody wyjścia — rozstrzygnięte 2026-08-04:** `0` sukces, `1` błąd użycia lub nieznany, `2` błąd konfiguracji (nie jest to repozytorium git, konflikt stanu przy `init`), `3` brak klucza, `4` błąd formatu (magic, `key_id`, nieznany bit `flags`, porażka tagu).
- **Wykrywanie stanu przez `init` — rozstrzygnięte 2026-08-04.** Stan tworzą cztery niezależne elementy: klucz w `.git/git-xcrypt/keys/`, wpisy `filter.git-xcrypt.*` w `.git/config`, plik `.git-xcrypt` i sekcja zarządzana w `.gitattributes`. Zamiast szesnastu przypadków obowiązują trzy reguły:
  - **Klucz istnieje → nigdy go nie ruszamy.** `init` naprawia pozostałe trzy elementy, raportuje co poprawił i kończy zerem. To jest odpowiedź na kontrargument z PRD FR-001: błąd w detekcji stanu nie może nadpisać klucza.
  - **Klucza brak, ale repozytorium nosi ślady wcześniejszej konfiguracji** (sekcja zarządzana w `.gitattributes` albo `.git-xcrypt` w HEAD) → to klon albo repozytorium po `lock`. Wygenerowanie nowego klucza uczyniłoby istniejące bloby nieodszyfrowywalnymi na zawsze, więc `init` **odmawia** z kodem `2` i wskazuje `unlock` / `import-key`.
  - **Klucza brak i śladów brak** → świeża inicjacja: klucz główny 32 B z CSPRNG, uprawnienia `0600`, wpisy w `.git/config` wraz z `required = true`, `.git-xcrypt` jeśli nie istnieje, synchronizacja `.gitattributes`.
  - Bez flagi `--force` na kluczu. Rotacja jest poza zakresem v0.1; flaga kasująca klucz to dokładnie ten tryb awarii, przed którym broni reguła pierwsza.
  - Repozytorium wykrywamy biblioteką (`gix-discover`), nie uruchomieniem `git` — wymóg samowystarczalności z „Założeń technicznych".
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

**Tryb każdego pliku jest zapisany w nim samym — bit 0 pola `flags`.** Rozstrzygnięte 2026-08-04. Smudge musi wiedzieć, czy dany plaintext **był** normalizowany, zanim zdecyduje o konwersji na wyjściu. Odczytywanie tego z `.git-xcrypt` w katalogu roboczym zawodzi na dwa sposoby, przy czym drugi jest rozstrzygający:

- **Rozjazd w czasie:** deklaracja zmieniona po zacommitowaniu plików. Plik binarny zadeklarowany później jako tekst dostałby przy checkoucie konwersję końców linii, której jego treść nigdy nie przeszła — czyli **uszkodzenie pliku binarnego**, wprost przeciw guardrailowi z PRD.
- **Wyścig przy checkoucie:** git nie gwarantuje kolejności zapisywania plików do katalogu roboczego. Smudge dla `sekrety/haslo.env` może wystartować **zanim** git zapisze `.git-xcrypt`. Przy `git clone` i przy przełączaniu gałęzi to nie jest przypadek teoretyczny.

Bit w nagłówku usuwa oba: plik jest samoopisujący, smudge nie czyta żadnego pliku konfiguracyjnego, a plik binarny nigdy nie dostanie konwersji, bo ma bit zerowy. Bit leży w AAD, więc jest uwierzytelniony. Determinizmu nie narusza — jego wartość wynika z deklaracji obowiązującej przy clean, a ta jest wersjonowana, więc identyczna na każdej maszynie.

**Deklaracja trybu należy do `.git-xcrypt`, nie do gita.** Skoro `-text` odbiera użytkownikowi atrybuty `text`/`eol` na plikach szyfrowanych, `.git-xcrypt` musi przejąć tę samą semantykę per wzorzec: `text`, `-text`, `eol=lf`, `eol=crlf` oraz zachowanie domyślne przy braku deklaracji. Nie wymyślamy własnego modelu — odtwarzamy ten, który użytkownik zna z `.gitattributes`, z tą różnicą, że `eol=*` działa u nas na wyjściu smudge, a nie w gicie. Deklaracja jest wersjonowana, więc jest jednakowa na wszystkich maszynach — i to jest warunek, pod którym powyższy niezmiennik trzyma.

**Konfigurację czytamy biblioteką, nie procesem potomnym.** `gix-config` (gitoxide) daje pełną precedencję system/global/repo/worktree wraz z `include`/`includeIf`, kompiluje się do środka binarki i nie łamie wymogu samowystarczalności z „Założeń technicznych". Wywoływanie `git config` odpada: git uruchamia nowy proces filtra na każdy plik, więc byłoby to N spawnów na ścieżce gorącej, najdroższych akurat na Windows. Pozostaje jedna binarka `git-xcrypt` w kilku trybach (`clean`, `smudge`, `diff` rejestrowane przez `init`; reszta wywoływana przez użytkownika); żadnego osobnego programu pomocniczego ani demona.

**Świadomie przyjęte ograniczenie:** plik o mieszanych końcach linii nie przetrwa round-tripu — normalizacja jest stratna, więc po `unlock` taki plik wróci inny niż był i `git status` pokaże zmianę. Git broni się przed tym przez `core.safecrlf`; czy odtwarzamy to ostrzeżenie, jest otwarte.

# Bezpieczeństwo i świadome ograniczenia

Wszystkie poniższe są **akceptowanymi kompromisami** konstrukcji, nie błędami:

- Wyciekają **metadane**: nazwy plików, ścieżki, rozmiary, daty commitów i fakt, że plik się zmienił. Rozmiar przecieka **dokładnie**, a nie w przybliżeniu: SIV szyfruje trybem CTR, więc `rozmiar bloba = 38 + rozmiar treści`, co do bajta.
- Szyfrowanie deterministyczne ujawnia, że dwa pliki mają identyczną treść, oraz że plik wrócił do poprzedniej wersji.
- **Największe realne ryzyko: sekret zacommitowany zanim wzorzec trafił do konfiguracji.** Zostaje w historii w postaci jawnej na zawsze. Przeciwdziałanie: `git-xcrypt status` wskazuje takie pliki, a dokumentacja opisuje procedurę czyszczenia historii i rotacji sekretu.
- Klucz w `.git/` jest tak bezpieczny jak dysk i konto użytkownika — narzędzie nie chroni przed skompromitowaną maszyną.
- Poza modelem zagrożeń: atakujący z dostępem do odszyfrowanego katalogu roboczego, ataki side-channel, ochrona przed samym hostingiem po `unlock` na CI.
- Sekrety nigdy nie trafiają do repozytorium projektu — również w testach i przykładach.

# Dystrybucja, licencja i nazewnictwo

- **Licencja — rozstrzygnięte 2026-08-04: `MIT OR Apache-2.0`** (dual, wybór po stronie odbiorcy), teksty w `LICENSE-MIT` i `LICENSE-APACHE`, deklaracja w `Cargo.toml`. Sprawdzone przed decyzją: AGWA/git-crypt ma w `COPYING` GPL-3.0, a `AprilNEA/git-crypt-rs` deklaruje w `Cargo.toml` `MIT OR Apache-2.0` — choć **nie dołącza żadnego pliku licencji**, więc GitHub raportuje dla tego repozytorium brak licencji; my tego błędu nie powtarzamy.
  - Copyleft GPL-3.0 nie sięga tego projektu, bo nie powstaje praca pochodna: nie bierzemy kodu ani formatu, a zgodne pozostają wyłącznie nazwy komend, model clean/smudge i UX — czyli warstwa funkcjonalna. Podpiera to CJEU C-406/10 (SAS v. World Programming, 2012): funkcjonalność programu, język programowania i **format plików danych** nie podlegają ochronie prawnoautorskiej. Analogicznie Google v. Oracle (US, 2021) dla odtworzenia deklaracji API.
  - **Warunek, pod którym to trzyma:** nie czytamy źródeł C++ `git-crypt` przy pisaniu odpowiadających im funkcji Rusta. Tłumaczenie funkcja po funkcji z otwartym oryginałem to jedyna droga, którą GPL mogłoby tu wejść. Wobec `git-crypt-rs` ryzyko jest tanie (MIT/Apache — wystarcza atrybucja), wobec `git-crypt` nie jest.
  - Wybór `MIT OR Apache-2.0` zamiast GPL-3.0: grant patentowy z Apache (istotny dla narzędzia kryptograficznego), zgodność z GPL-2.0 z MIT, `lib` publikowalna na crates.io bez zobowiązań dla odbiorcy oraz brak sugestii pokrewieństwa z oryginałem, którego nie ma. Zastrzeżenie: to nie jest porada prawna.
- Atrybucja projektów inspirujących w README niezależnie od wyniku analizy licencyjnej.
- **Kolizja nazw — rozstrzygnięte 2026-08-04: crate i binarka nazywają się `git-xcrypt`.** Sprawdzone przed decyzją: `git-crypt` na crates.io jest **zajęte** przez `AprilNEA/git-crypt-rs` (0.1.4, ostatnia aktualizacja 2025-11-15), a binarki `git-crypt` i `git-secret` mają formuły w Homebrew — plik wykonywalny o którejkolwiek z tych nazw byłby po cichu przesłaniany na `PATH` przez wcześniejszy wpis. `git-xcrypt` jest wolne na crates.io, nie ma formuły w Homebrew i nie znaleziono kolidującego projektu. Nazwa zachowuje mechanizm podkomendy: binarka `git-xcrypt` na `PATH` daje `git xcrypt <komenda>`.
- Homebrew wymaga własnego tapa (do core trafiają tylko projekty z ustaloną popularnością).
- Wydania z GitHub Actions: podpisane artefakty, sumy kontrolne SHA-256, spójne wersjonowanie tagu i `Cargo.toml`.

# Jakość i testy

- Testy integracyjne na **prawdziwych repozytoriach git** w katalogu tymczasowym: init → dodanie sekretu → commit → sprawdzenie, że blob w obiekcie gita jest zaszyfrowany → clone → unlock → porównanie treści.
- Testy właściwości: `decrypt(encrypt(x)) == x` oraz `encrypt(x) == encrypt(x)` (determinizm).
- Wektory testowe formatu zamrożone w repo — chronią przed przypadkową zmianą formatu psującą istniejące repozytoria. Osobno **zamrożone wektory z RFC 5297 Appendix A**: sprawdzają, że crate liczy dokładnie to, co mówi specyfikacja. To najtańsza dostępna namiastka audytu warstwy SIV, której NCC Group nie przejrzało.
- CI na wszystkich trzech platformach: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo audit`, `cargo deny check licenses` (pilnuje, by copyleft nie wszedł bocznymi drzwiami z zależnością i nie unieważnił wyboru `MIT OR Apache-2.0`).
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

1. **Format odbiorców: age, `crypto_box` czy OpenPGP (sequoia)?** Odbiorcy są poza zakresem v0.1, więc pytanie **nie blokuje niczego** — rozstrzygamy je dopiero, gdy wejdą do zakresu. Wtedy realny konflikt: `age` jest wygodny i interoperacyjny, ale spoza RustCrypto; `crypto_box` mieści się w regule, ale oznacza własny format koperty. Format pliku zaszyfrowanego jest niezależny od tego wyboru.
2. ~~**Nazwa crate'a i binarki** wobec kolizji z oryginalnym `git-crypt`.~~ Rozstrzygnięte 2026-08-04: `git-xcrypt` dla obu — patrz „Dystrybucja, licencja i nazewnictwo".
3. ~~**Licencja projektu** po weryfikacji licencji projektów inspirujących.~~ Rozstrzygnięte 2026-08-04: `MIT OR Apache-2.0` — patrz „Dystrybucja, licencja i nazewnictwo".
4. ~~Nazwa pliku konfiguracyjnego.~~ Rozstrzygnięte 2026-08-04: plik nazywa się `.git-xcrypt`, a koperty kluczy — gdyby kiedykolwiek powstały — trafiają do `.git-xcrypt-keys/`. To usuwa kolizję, która była istotą tego pytania: plik i katalog o identycznej nazwie nie mogą współistnieć.
5. **Próg rozmiaru pliku, powyżej którego przechodzimy na buforowanie dyskowe zamiast RAM.** Zaostrzone 2026-08-04: `aes-siv` 0.7 ma API jednorazowe, więc dziś każdy plik trafia do RAM w całości. Rozwiązania są dwa i oba mieszczą się w formacie: buforowanie na dysku albo nowy `suite` z trybem blokowym. Do rozstrzygnięcia przy implementacji, nie blokuje `S-01`.
6. Które komendy z oryginału poza listą MVP faktycznie chcemy odtworzyć.
7. **Zachowanie domyślne przy braku deklaracji EOL w `.git-xcrypt`**: traktować plik jako binarny (żadnej konwersji, bezpieczne) czy jako `text=auto` z heurystyką gita (NUL w pierwszych 8000 bajtach)? Heurystyka nie łamie determinizmu — ta sama treść daje tę samą decyzję — ale jest cicha: dopisanie bajtu zerowego przełącza tryb i zmienia cały ciphertext. Patrz „Końce linii (LF/CRLF)".
8. **Czy odtwarzamy ostrzeżenie `core.safecrlf`** dla plików o mieszanych końcach linii, które nie przetrwają round-tripu.
