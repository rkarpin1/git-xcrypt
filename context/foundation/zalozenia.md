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
- Inicjacja projektu ma być prosta — wystarcza `git-xcrypt init`. Nie powstają żadne dodatkowe skrypty pomocnicze ani programy pomocnicze. **Zastrzeżenie z 2026-08-04:** sekcja zarządzana w `.gitattributes` jest jednak plikiem, którego trzeba pilnować — po każdej zmianie wzorców należy uruchomić `sync` (albo `sync --check` w CI). Powód i koszt pominięcia: „Integracja z git" → „Konstrukcja catch-all".
- Wymagany klucz repozytorium jest generowany automatycznie przy inicjacji.
- Konfiguracja plików i katalogów do szyfrowania opiera się na **własnym pliku konfiguracyjnym o składni podobnej do `.gitignore`**, nazwanym `.git-xcrypt`. Jest to świadome odejście od oryginału, który wymaga ręcznej edycji `.gitattributes`.
  - Plik `.git-xcrypt` jest wersjonowany w repozytorium i jest **jedynym źródłem prawdy** o tym, co jest szyfrowane. Nie jest tłumaczony na wpisy w `.gitattributes` — czyta go bezpośrednio filtr, przy każdym `git add`. **Selekcja** — czyli to, które ścieżki są szyfrowane — działa natychmiast, bez komendy synchronizującej. Linie per wzorzec w `.gitattributes` to osobna sprawa i **wymagają `sync`**; dlaczego, i co kosztuje ich pominięcie: „Integracja z git" → „Konstrukcja catch-all".
  - Wzorce mają semantykę `.gitignore`. Dopasowaniem pojedynczego wzorca zajmuje się `gix-glob` (gitoxide) — ten sam wildmatch, którego używa git — natomiast **semantykę samego pliku** (pływanie wzorca bez ukośnika, wygrywa ostatnie dopasowanie, negacje) odtwarza `src/config.rs`. Zapisane wcześniej „`gix-ignore`" jest nieprawdziwe: tego crate'a nie ma w `Cargo.toml`. Rozróżnienie nie jest kosmetyczne — to stąd bierze się cała klasa błędu „rendering `.gitattributes` nie sięga tak daleko jak filtr", opisana niżej. Wzorzec katalogowy `sekrety/` obejmuje katalog i wszystko pod nim; wiodący `/` kotwiczy do korzenia repozytorium; ostatnie dopasowanie wygrywa.
  - Negacje (`!plik`) są **obsługiwane**, na zasadzie ostatniego dopasowania. Odrzucanie ich zmuszałoby do przebudowy wzorców tam, gdzie wyjątek jest naturalny (`sekrety/` plus jawny `README.md`). W zamian `status` wypisuje ścieżki wyłączone negacją w osobnej sekcji, żeby wyjątek nigdy nie był niewidoczny.
  - Po wzorcu mogą stać atrybuty końców linii — składnia i semantyka w „Końce linii (LF/CRLF)" → „Składnia `.git-xcrypt`".
- Pozostałe komendy `git-xcrypt` mają odpowiadać projektom źródłowym co do nazwy i zachowania, ale każda wymaga oddzielnej dyskusji i potwierdzenia przed implementacją.

# Zakres MVP / poza zakresem

**W zakresie v0.1:**

- `git-xcrypt init` — generuje klucz repozytorium, rejestruje filtry w `.git/config` (w tym `filter.git-xcrypt.process` i `required = true`), tworzy `.git-xcrypt` (jeśli brak) i wpisuje do `.gitattributes` statyczną linię catch-all.
- `git-xcrypt status` — rozstrzygnięte 2026-08-04, cztery zadania:
  - **kompletność konfiguracji** — czy `filter.git-xcrypt.*` jest w `.git/config`. Bez tego klon, w którym nie uruchomiono `init`/`unlock`, przepuszcza treść mimo linii catch-all w `.gitattributes`.
  - **skan całej osiągalnej historii** — czy pliki dziś szyfrowane występowały kiedyś w repozytorium w postaci jawnej. Sprawdzenie płytkie odpada: sekret zacommitowany przed konfiguracją albo później usunięty z `HEAD` jest w `HEAD` niewidoczny, a nadal leży w historii i nadal jest u hostingodawcy. Skan nie wymaga deszyfrowania — wystarczy sprawdzić 11 bajtów magic na początku każdego bloba, którego ścieżka pasuje do wzorca, więc koszt zależy od liczby obiektów, nie od ich rozmiaru.
  - **`--fix` dla naprawy bezpiecznej** — pliki pasujące do wzorca, a leżące jawnie w `HEAD` lub indeksie, zostają ponownie dodane, więc od następnego commita są szyfrowane. Operacja lokalna, bez przepisywania historii. Flaga siedzi przy `status`, bo diagnoza i naprawa dzielą całą analizę.
  - **sekcja `undetermined`** — dodana przy implementacji i nośna dla werdyktu: „nie dało się ustalić" nigdy nie może być raportowane jako „nic złego się nie dzieje". Trafiają tu klon płytki i częściowy, split index, nieczytelny indeks, niewyliczalny magazyn referencji i brak `.git-xcrypt`. Od 2026-08-04 ma **własny kod wyjścia `6`**, patrz „Integracja z git" → kody wyjścia.
  - Przy znalezisku kod wyjścia `5`, przy „nie dało się ustalić" `6` — pozwala wpiąć komendę w CI jako bramkę i odróżnia ekspozycję od błędu narzędzia oraz od niezbadanego checkoutu. Pełny skan historii wymaga pełnego klonu (`fetch-depth: 0` w `actions/checkout`); bez tego `status` uczciwie kończy `6`.
  - **Granica do udokumentowania:** `status` odpowiada na pytanie „czy moje deklaracje są egzekwowane", a nie „czy w repozytorium są sekrety". Plik, który nigdy nie pasował do żadnego wzorca, jest dla tej komendy niewidzialny.
- `git-xcrypt lock` — usuwa klucz z repo i zaszyfrowuje pliki w katalogu roboczym.
- `git-xcrypt unlock` — wczytuje klucz i odszyfrowuje pliki w katalogu roboczym.
- `git-xcrypt export-key` / `import-key` — eksport i import klucza symetrycznego do przenoszenia między maszynami.
- `git-xcrypt sync` — regeneruje sekcję w `.gitattributes` na podstawie `.git-xcrypt`. Tryb **`--check`** niczego nie zapisuje i kończy `1` na nieaktualnej sekcji, do użycia jako bramka CI.
- `git-xcrypt diff` — sterownik `textconv` rejestrowany przez `init`, dzięki któremu `git diff` i `git log -p` porównują treść jawną (FR-006). Nie jest wołany ręcznie. Odmawia, gdy wskazany plik **zawiera klucz** — sprawdzane po treści, w dokładnie tym zestawie kształtów, jakie przyjmuje parser, nie po położeniu pliku; kontrola po ścieżce przeciekała klucz przy uruchomieniu spoza repozytorium.
- `git-xcrypt process` — sam filtr długożyjący, rejestrowany przez `init` jako `filter.git-xcrypt.process`. Też nie jest wołany ręcznie: wszystko, co pisze na `stdout`, jest protokołem.

**Poza zakresem v0.1** (do świadomego odłożenia, nie do cichego pominięcia):

- **Zarządzanie odbiorcami (`add-user` / `list-users`, koperty kluczy) oraz klucze per użytkownik i per stanowisko.** Rozstrzygnięte 2026-08-04 zgodnie z `prd.md` §Non-Goals — wcześniej ten dokument wymieniał je w zakresie v0.1, co było sprzecznością z PRD. Model v0.1 jest jednoosobowy, klucz przenosi się plikiem. Format pliku zaszyfrowanego jest na to gotowy: koperty pakują klucz główny i nie dotykają szyfrowania treści (patrz „Zarządzanie kluczami").
- Wsparcie dla zewnętrznego `gpg` i keyringu OpenPGP użytkownika.
- Wiele niezależnych kluczy w jednym repo (`--key-name`).
- Migracja repozytoriów zaszyfrowanych oryginalnym `git-crypt`.
- Rotacja klucza i wycofywanie dostępu odbiorcy z przepisaniem historii.
- **Natywne czyszczenie historii z jawnych wersji plików.** Rozstrzygnięte 2026-08-04. W v0.1 `status` **raportuje** ekspozycję — ścieżki, commity, bloby — wypisuje gotowe polecenie dla zewnętrznego `git-filter-repo` i checklistę zaczynającą się od rotacji sekretu. Sama operacja zostaje poza zakresem z dwóch powodów: przepisanie historii to własny odpowiednik `git-filter-repo` w Ruście, czyli osobny element roadmapy wielkości `S-01` (wywołanie zewnętrznego narzędzia odpada przez wymóg samowystarczalnej binarki), a przede wszystkim **nie jest tym, czym się wydaje** — czyści repozytorium, ale nie cofa wycieku: sekret zostaje w forkach, cache'ach, logach CI i cudzych klonach. Jedyną realną naprawą jest rotacja sekretu. Gdy funkcja powstanie, dostanie własną komendę o nazwie mówiącej, co robi (`purge-history`), a nie „naprawia".

# Założenia techniczne

- Aplikacja napisana w Rust, działa na Windows, macOS i Linux.
- Edycja Rust 2024; **MSRV = 1.88**, utrzymywany zadaniem `msrv` w CI (`.github/workflows/ci.yml`) i zadeklarowany w `Cargo.toml`. Nie 1.85, mimo że tyle wymaga sama edycja: kod używa `let`-chain w warunkach `if`, stabilnych dopiero od 1.88 — zmierzone, na 1.85 crate nie kompiluje się w ogóle.
- Struktura: `lib` (logika, testowalna) + cienki `bin` (parsowanie argumentów, kody wyjścia).
- Obsługa błędów: `thiserror` w bibliotece, czytelne komunikaty w binarce. Brak `unwrap()`/`panic!` na ścieżkach obsługujących dane wejściowe.
- **Zero `unsafe`** w kodzie własnym, szczególnie w warstwie kryptograficznej. Kryptografia **wyłącznie z crate'ów RustCrypto**, nigdy implementowana samodzielnie — nie piszemy prymitywów ani nie składamy własnych konstrukcji z prymitywów. Sformułowanie „wyłącznie z audytowanych bibliotek" byłoby nieprawdziwe: audyt NCC Group z 2020 objął `aes-gcm` i `chacha20poly1305`, natomiast wybrany `aes-siv` audytu **nie ma** i jest to świadomie przyjęte ryzyko — uzasadnienie w „Kryptografia i format pliku".
- Instalacja przez `cargo install` (dziś `cargo install --path .`; crate nie jest jeszcze opublikowany na crates.io).
- Pliki wykonywalne budowane w GitHub Actions dla każdej platformy — `.github/workflows/release.yml` buduje pięć targetów (Linux musl x86_64 i aarch64, macOS x86_64 i aarch64, Windows MSVC), pakuje je z sumami SHA-256 i publikuje przy tagu `v*`. **Podpisywania artefaktów jeszcze nie ma** — kontrargument z PRD FR-011 czeka na prawdziwą tożsamość podpisującą, a nie na krok w workflow, który tylko udaje.
- Binaria muszą być samowystarczalne: bez wymaganych bibliotek zewnętrznych i bez wywoływania zewnętrznych procesów (w tym `gpg`). Linux: preferowany target `musl` dla statycznego linkowania.
- Docelowo instalacja standardowymi narzędziami każdej z platform (brew itp.) — jeszcze nie istnieje, wymaga wydania i własnego tapa.

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
- **Wiodący NUL** sprawia, że git rozpoznaje plik jako binarny, więc `git diff` bez klucza pokaże `Binary files differ` zamiast szumu. Uwaga na dwie różne heurystyki gita: `git diff` bada pierwsze 8000 bajtów, natomiast ścieżka konwersji CRLF skanuje całą treść — zmierzone, patrz „Końce linii".
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

## Zabezpieczenia `lock` — rozstrzygnięte 2026-08-04

`lock` usuwa **jedyną** kopię klucza: `.git/` nie jest wersjonowane ani pushowane, więc po tej komendzie odszyfrowanie całej dotychczasowej historii zależy wyłącznie od kopii spoza repozytorium. Nazwa myli, bo sugeruje symetrię — `unlock` tego nie cofnie. Strata jest przy tym odroczona: nic nie psuje się w momencie wykonania, prawda wychodzi przy próbie odblokowania, może po miesiącach. Stąd trzy zabezpieczenia:

- **Domyślnie interaktywny, z potwierdzeniem przez wpisanie `yes`.** Flaga `--yes` przełącza w tryb nieinteraktywny (konwencja z `apt`/`dnf`; `--force` sugerowałoby obchodzenie zabezpieczenia, a tu chodzi o pominięcie pytania). Ostrzeżenie jest wypisywane **w obu trybach** — w nieinteraktywnym na `stderr`.
- **Ostrzeżenie podaje `key_id`, nigdy sam klucz.** Rozważano wypisanie klucza jako ostatniej szansy na kopię i **odrzucono**: klucz zostawałby w scrollbacku terminala i buforze multipleksera, `git-xcrypt lock > lock.log` uruchomione wewnątrz repozytorium położyłoby go do drzewa roboczego (scenariusz wycieku opisany przy PRD FR-007), a w trybie nieinteraktywnym trafiałby do logu CI. `key_id` identyfikuje klucz jednoznacznie i jest dla atakującego bezwartościowy, a komunikat kieruje do `export-key`, który zapisuje klucz do pliku z uprawnieniami `0600`. Reguła „klucz nigdy na `stdout` poza `export-key`" zostaje nienaruszona.
- **Odmowa przy niezacommitowanych zmianach.** `lock` zamienia pliki robocze na zaszyfrowane, więc niezapisane zmiany w plikach objętych wzorcem nie istnieją w żadnym blobie i przepadłyby razem z plaintextem — druga ścieżka utraty danych w tej samej komendzie, niezależna od klucza. `lock` odmawia i wypisuje listę takich plików. **Flaga `--yes` tego nie obchodzi**: to inne ryzyko niż utrata klucza i zasługuje na osobną decyzję użytkownika.

Kody wyjścia: przerwanie przez użytkownika → `1`, nic nie zmienione; brudny katalog roboczy → `2`.

Szkic komunikatu:

```
WARNING: lock deletes the only copy of this repository's key.

  key_id: 3fa9120b7ec4558a
  path:   .git/git-xcrypt/keys/default

After this, decrypting anything — including the entire history — will be
possible only from a copy of the key held outside this directory.
unlock WILL NOT UNDO THIS.

If you do not have a copy, abort and run:
  git-xcrypt export-key ~/keys/git-xcrypt-3fa9120b.key

Type `yes` to delete the key:
```

- Klucz repozytorium leży w `.git/git-xcrypt/keys/` — **nigdy** nie jest commitowany. Katalog `.git/` nie podlega wersjonowaniu, ale aplikacja dodatkowo pilnuje, by klucz nie trafił do drzewa roboczego.
- Uprawnienia pliku klucza: `0600` na systemach uniksowych; na Windows odpowiednie ACL ograniczone do właściciela.
- Klucz nigdy nie jest wypisywany na `stdout` poza jawną komendą `export-key`.
- **Odbiorcy natywnie w Rust, bez zewnętrznego `gpg`** — poza zakresem v0.1, patrz „Zakres MVP". Gdy wejdą: koperta pakuje **klucz główny 32 B**, więc jest niezależna zarówno od wybranego szyfru, jak i od formatu pliku danych; dodanie odbiorców nie wymaga żadnej zmiany w formacie zaszyfrowanego pliku. Kandydat: format **age** (crate `age`, odbiorcy X25519) — mały, nowoczesny, bez zależności systemowych, ale **spoza RustCrypto**, co koliduje z regułą z „Założeń technicznych". Odpowiednikiem wewnątrz RustCrypto byłby `crypto_box` (X25519 + XSalsa20-Poly1305) kosztem własnego, nieinteroperacyjnego formatu koperty. Sequoia (OpenPGP) daje zgodność z kluczami GPG kosztem znacznie większego nakładu i rozmiaru binarki. **Rozstrzygnięcie odłożone do momentu, w którym odbiorcy wejdą do zakresu** — patrz „Otwarte decyzje".
- **Gdy odbiorcy wejdą do zakresu:** klucz repozytorium będzie szyfrowany osobno dla każdego z nich, a koperty trafią do katalogu `.git-xcrypt-keys/` w repozytorium, żeby każdy uprawniony mógł wykonać `unlock` po sklonowaniu. W v0.1 nic z tego nie istnieje — w kodzie jest wyłącznie zarezerwowana nazwa katalogu na liście nigdy-nie-szyfrowanych. Katalog **nie** może nazywać się `.git-xcrypt/` — tę nazwę zajmuje plik konfiguracyjny, a plik i katalog o tej samej nazwie nie mogą współistnieć.
- Gdy powstaną, dodanie odbiorcy da mu dostęp do **całej historii**, nie tylko do commitów od momentu dodania — klucz repozytorium jest jeden i niezmienny. Analogicznie usunięcie odbiorcy nie odbiera dostępu do tego, co już sklonował; wymaga rotacji klucza. Obie własności muszą być jasno opisane w dokumentacji użytkownika.

# Integracja z git

- Mechanizm: filtr i sterownik `diff` zarejestrowane w `.git/config`, aktywowane wpisami w `.gitattributes`. `init` zapisuje **cztery** klucze: `filter.git-xcrypt.process`, `filter.git-xcrypt.required = true`, `diff.git-xcrypt.textconv` oraz `diff.git-xcrypt.cachetextconv = false`. Kluczy `filter.*.clean` i `filter.*.smudge` nie zapisujemy nigdy — `clean` i `smudge` to komendy **wewnątrz** protokołu długożyjącego, nie tryby binarki.
- **`cachetextconv = false` jest wpisywane jawnie i jest decyzją bezpieczeństwa, nie porządkiem.** Zmierzone: przy `true` git trzyma **odszyfrowaną** treść każdego pliku jako bloby pod `refs/notes/textconv/git-xcrypt`, czyli wewnątrz `.git/`, gdzie przeżywają `lock` — plaintext, przed którym cały produkt broni, wraca na dysk po skasowaniu klucza. Samo pominięcie klucza nie wystarcza: `[diff "git-xcrypt"] cachetextconv = true` w `~/.gitconfig` jest dziedziczone i przesłania je dopiero lokalne `false`.

## Konstrukcja catch-all — rozstrzygnięte 2026-08-04

Rozwiązuje PRD Open Question 1 („jak nie dopuścić do rozjazdu `.git-xcrypt` i `.gitattributes`") — nie przez procedurę pilnowania, tylko przez usunięcie rozjazdu z konstrukcji.

Sekcja zarządzana w `.gitattributes` wygląda tak:

```
# >>> git-xcrypt >>>
* filter=git-xcrypt
**/sekrety/** -text diff=git-xcrypt
*.env -text diff=git-xcrypt
**/*.env/** -text diff=git-xcrypt
# <<< git-xcrypt <<<
```

Rendering jest mniej ładny, niż wyglądał w pierwszej wersji tego dokumentu, i to nie przypadkiem — **musi sięgać dokładnie tam, gdzie sięga filtr**. Wzorzec `.gitignore` bez własnego ukośnika pływa, więc `sekrety/` obejmuje też `app/sekrety/x` i renderuje się jako `**/sekrety/**`; `*.env` może nazywać także katalog, więc dostaje **dwie** linie. Negacja renderuje się jako `<wzorzec> !text !diff` (plik jest jawny, więc git ma nim zarządzać po swojemu), `binary` dokłada `-diff`, a wzorzec zaczynający się od `[attr]` jest cytowany. Autorytetem jest tu `src/gitattributes.rs` wraz z testami, które pytają o wynik prawdziwego `git check-attr`.

- **Linia `* filter=git-xcrypt` jest statyczna.** Pisze ją `init` raz i nigdy więcej nie rusza. Nie zależy od treści `.git-xcrypt`, więc **nie ma jak się z nią rozjechać**. Na niej i tylko na niej wisi bezpieczeństwo.
- **Filtr decyduje sam**, czytając `.git-xcrypt`. Ścieżkę dostaje w nagłówku `pathname=` protokołu długożyjącego, jako **surowe bajty** (nie `String` — nazwa pliku nie musi być poprawnym UTF-8, a dwa realne błędy wzięły się właśnie stąd). Zapisane wcześniej `%f` dotyczyło prototypu `clean`/`smudge` i przy `filter.<driver>.process` nie występuje. **Selekcja działa natychmiast, bez `sync`.**
- **Linie per wzorzec (`-text`, `diff`) nie są opcjonalne — korekta z 2026-08-04.** Nazywamy je kosmetycznymi, bo ich rozjazd nie zapisuje sekretu jawnie, i tyle ta nazwa znaczy. `-text` jest tym, co trzyma własną konwersję CRLF gita z dala od ciphertextu. **Zmierzone na git 2.55:** ścieżka szyfrowana bez `-text`, przy dowolnym innym źródle atrybutów deklarującym ją jako `text`, dostaje konwersję na ciphertexcie — na pliku 2 MB zjadło to 34 bajty `CR`, `git add` skończyło **kodem 0**, uszkodzony blob został zacommitowany, a przy checkoucie tag nie przeszedł i **plik zniknął**, nieodwracalnie. Wniosek wiążący: **wygenerowane linie muszą pokrywać dokładnie ten zbiór ścieżek, który szyfruje filtr** — ani węższy (uszkodzenie ciphertextu), ani szerszy (`-text` na plikach jawnych).
- **`sync` (FR-003) jest więc częścią przepływu, nie ozdobą**, i należy go uruchamiać po każdej zmianie wzorców; `sync --check` kończy `1` na nieaktualnej sekcji i nadaje się na bramkę CI, a `status` wypisuje o tym notę.

Zmierzone na git 2.55 (repozytoria tymczasowe, nie na tym projekcie), 2026-08-04:

| Pomiar | Wynik |
| --- | --- |
| Czy `git add` utrwala treść przed commitem? | **Tak** — po samym `git add` plaintext leży już jako obiekt w `.git/objects` |
| Tryb awarii: wzorzec tylko w `.git-xcrypt`, brak wpisu w `.gitattributes` | **Potwierdzony.** Filtr nieuruchomiony, `git add` i `commit` z **kodem 0**, plaintext w bazie obiektów, zero sygnału dla użytkownika |
| Czy `* filter=xc` uruchamia filtr dla każdego pliku? | **Tak**, dla wszystkich, łącznie z samym `.gitattributes`; ścieżka jest względem korzenia (pomiar na prototypie `clean`/`smudge` z `%f`; przy `process` tę samą ścieżkę niesie `pathname=`) |
| Czy `.gitattributes` działa z katalogu roboczego bez dodania do indeksu? | **Tak** |
| Czy `pre-commit` daje weto? | **Tak**, ale `--no-verify` obchodzi je w całości i plaintext ląduje w commicie |
| `filter.<driver>.process` (filtr długożyjący) na 2.55 | **Obsługiwany** — 12 plików obsłużył jeden proces |

Wydajność, `git add -A` na 2000 plików: bez filtra **540 ms**, catch-all z procesem na plik **12 105 ms** (22×), catch-all z filtrem długożyjącym **596 ms** (+10%, i to filtr prototypowy w Pythonie).

Konsekwencje wiążące:

- **Filtr rejestrujemy jako `filter.git-xcrypt.process`** — protokół długożyjący, jeden proces na całą operację. To warunek wykonalności, nie optymalizacja: 22× dyskwalifikuje. Na Windows różnica będzie większa, bo spawn procesu jest tam droższy.
- **Twarda reguła: przepuszczanie treści musi być tożsamościowe co do bajta.** Przy catch-all promień rażenia błędu filtra rośnie z „pliki szyfrowane" na **wszystkie pliki w repozytorium**. Obowiązkowy test właściwości `passthrough(x) == x` dla dowolnych bajtów, w tym pustych, wielkich i binarnych.
- **`required = true` na catch-all znaczy, że awaria filtra blokuje każdą operację gita w repozytorium.** To jest zamierzone — bez tego nie ma gwarancji z PRD §Guardrails. Zapisane w `README.md` §Known limitations wraz z procedurą ratunkową (`git config --unset filter.git-xcrypt.process` i `…required`) oraz ostrzeżeniem, że wszystko zacommitowane przy wyrejestrowanym filtrze idzie do repozytorium jawnie.
- **Twarde wykluczenia:** `.gitattributes`, `.git-xcrypt` i `.git-xcrypt-keys/` nigdy nie są szyfrowane, niezależnie od wzorców — są potrzebne do bootstrapu, a git wywołuje filtr również dla nich (zmierzone).
- **Wszystko, co niebezpieczne, smudge czyta z nagłówka pliku, nie z `.git-xcrypt`** — czy odszyfrować i czy treść była normalizowana. To likwiduje wyścig przy checkoucie w tej jego części, która mogłaby uszkodzić plik. **Doprecyzowanie z 2026-08-04:** wcześniejsze „smudge nie czyta `.git-xcrypt` w ogóle" jest nieprawdziwe i sprzeczne z decyzją niżej, że `eol=` celowo nie trafia do nagłówka. Smudge czyta z deklaracji dwie rzeczy: `eol=` dla tej ścieżki oraz to, czy ścieżka jest zadeklarowana (żeby ostrzec o pliku leżącym jawnie). Obie są nieszkodliwe przy wyścigu, bo zły wybór końca linii jest samonaprawialny — następny clean i tak normalizuje do LF. Brak lub nieczytelny `.git-xcrypt` na ścieżce clean → błąd i przerwanie operacji, nigdy przepuszczenie treści.
- **Żadnego haka `pre-commit`.** `--no-verify` obchodzi go w całości, a treść i tak jest utrwalana już przy `git add`. Haki nie są wersjonowane i nie pojawiają się po klonie. Mechanizm atrybutowy wymusza git sam i nie ma flagi wyłączającej go przez roztargnienie.

**Ryzyko, którego ta konstrukcja nie usuwa:** klon bez uruchomionego `init` / `unlock` ma `.gitattributes` z linią catch-all, ale nie ma wpisów `filter.git-xcrypt.*` w `.git/config`, bo `.git/config` nie jest wersjonowane. Git traktuje wtedy niezdefiniowany filtr jako brak filtra i przepuszcza treść. Commit sekretu z takiego klonu daje plaintext. Przeciwdziałanie: `status` (FR-010) sprawdza kompletność konfiguracji, a dokumentacja mówi wprost, że klon bez `unlock` nie jest bezpieczny do zapisu.
- **Twarda reguła: na ścieżce clean/smudge nic poza danymi nie może trafić na `stdout`.** Żadnych `println!`, logów, pasków postępu. Diagnostyka wyłącznie na `stderr`. Naruszenie tej reguły cicho uszkadza pliki użytkownika.
- Filtr musi być odporny na wielokrotne uruchomienie: szyfrowanie już zaszyfrowanej treści i deszyfrowanie plaintextu to przypadki do wykrycia i obsłużenia — tabela zachowań w „Kryptografia i format pliku" → „Idempotencja po nagłówku".
- **Kody wyjścia — rozstrzygnięte 2026-08-04, rozszerzone 2026-08-04 o kod `6`:** `0` sukces, `1` błąd użycia lub nieznany, `2` błąd konfiguracji lub konfliktu stanu (nie jest to repozytorium git, konflikt przy `init`, brudny katalog roboczy przy `lock`), `3` brak klucza, `4` błąd formatu (magic, `key_id`, nieznany bit `flags`, porażka tagu), `5` znaleziono ekspozycję (`status` wykrył jawne wersje w historii albo pliki niezaszyfrowane mimo wzorca), `6` **nie dało się ustalić** (`status` nie mógł odpowiedzieć na pytanie).
  - **Rozszerzenie tabeli 2026-08-04 — świadome złamanie zamrożenia, przed pierwszym wydaniem.** Powód jest zmierzony: `5` niósł dotąd obie odpowiedzi naraz, więc **zdrowy `git clone --depth 1` kończył piątką**, a `actions/checkout` klonuje płytko, dopóki nie dostanie `fetch-depth: 0` — czyli domyślna konfiguracja CI nie przechodziła bramki, którą ta komenda ma być. Bramka, która alarmuje na własnej konfiguracji domyślnej, zostaje wyłączona. Odrzucona alternatywa: zdegradowanie płytkiego i częściowego klonu do noty — to samo „nie dało się ustalić" trafiłoby wtedy do kodu `0`, czyli dokładnie do odpowiedzi, której `status` nigdy nie może udzielić. Koszt rozszerzenia jest dziś zerowy (nie istnieje żaden odbiorca poza tym repozytorium), po wydaniu byłby zmianą łamiącą.
  - **`5` znaczy odtąd wyłącznie ekspozycję**, a `6` — klon płytki, klon częściowy, podzielony indeks, indeks nieczytelny, magazyn referencji, którego nie da się wyliczyć, referencja nierozwiązywalna, brak `.git-xcrypt`. **Znalezisko wygrywa z niewiadomą**: przebieg, który jednocześnie znalazł wyciek i nie zdołał odczytać indeksu, kończy `5`. Kierunek odwrotny osłabiałby bramkę po cichu.
  - Komunikat rozstrzyga to samo bez czytania kodu: werdykt `undetermined` mówi wprost `NOTHING WAS FOUND, and nothing is ruled out either`, bo dwie odpowiedzi wymagają dwóch różnych reakcji operatora — `5` mówi „rotuj sekret", `6` mówi „napraw checkout i zapytaj ponownie".
- **Wykrywanie stanu przez `init` — rozstrzygnięte 2026-08-04.** Stan tworzą cztery niezależne elementy: klucz w `.git/git-xcrypt/keys/`, wpisy `filter.git-xcrypt.*` w `.git/config`, plik `.git-xcrypt` i sekcja zarządzana w `.gitattributes`. Zamiast szesnastu przypadków obowiązują trzy reguły:
  - **Klucz istnieje → nigdy go nie ruszamy.** `init` naprawia pozostałe trzy elementy, raportuje co poprawił i kończy zerem. To jest odpowiedź na kontrargument z PRD FR-001: błąd w detekcji stanu nie może nadpisać klucza.
  - **Klucza brak, ale repozytorium nosi ślady wcześniejszej konfiguracji** (sekcja zarządzana w `.gitattributes` albo obecność `.git-xcrypt` — **w drzewie roboczym**, nie w `HEAD`, jak mówiła pierwsza wersja tego zapisu; implementacja jest tu ostrożniejsza, bo brak wpisu w `HEAD` nie dowodzi niczego w repozytorium bez commitów) → to klon albo repozytorium po `lock`. Wygenerowanie nowego klucza uczyniłoby istniejące bloby nieodszyfrowywalnymi na zawsze, więc `init` **odmawia** z kodem `2` i wskazuje `unlock` / `import-key`.
  - **Klucza brak i śladów brak** → świeża inicjacja: klucz główny 32 B z CSPRNG, uprawnienia `0600`, wpisy w `.git/config` wraz z `required = true`, `.git-xcrypt` jeśli nie istnieje, synchronizacja `.gitattributes`.
  - Bez flagi `--force` na kluczu. Rotacja jest poza zakresem v0.1; flaga kasująca klucz to dokładnie ten tryb awarii, przed którym broni reguła pierwsza.
  - Repozytorium wykrywamy biblioteką (`gix-discover`), nie uruchomieniem `git` — wymóg samowystarczalności z „Założeń technicznych".
- **Twarda reguła: filtr rejestrujemy z `filter.git-xcrypt.required = true`.** Wbrew intuicji sam niezerowy kod filtra **nie** przerywa operacji gita. Zmierzone na git 2.55 (repozytorium tymczasowe, nie na tym projekcie): bez tej flagi filtr `clean` kończący się kodem `3` daje `git add` **kod wyjścia 0**, git traktuje awarię jako nieszkodliwą i przepuszcza treść bez zmian — do indeksu i do bazy obiektów trafia **plaintext**, a użytkownik widzi tylko `error:` w szumie i udany commit. Z flagą: `fatal: <plik>: clean filter 'git-xcrypt' failed`, plik nie wchodzi do indeksu, żaden obiekt nie powstaje. Zabezpieczenie „błąd przerywa operację" jest więc własnością tej flagi, a nie samego gita — jej ustawienie należy do `init` i jest warunkiem gwarantki z PRD §Guardrails, nie detalem konfiguracji. Regresji pilnują dwa testy w `tests/filter_edge_cases.rs`; usunięcie flagi z harnessu wywala oba.
- `.gitattributes` dla plików szyfrowanych musi zawierać `-text`, żeby `core.autocrlf` na Windows nie modyfikował ciphertextu — patrz „Końce linii (LF/CRLF)", gdzie opisany jest zmierzony mechanizm i jego konsekwencje.
- **Zakładamy prawdziwego gita — rozstrzygnięte 2026-08-04.** Gwarancje tego narzędzia obowiązują dla klientów, które wywołują plik wykonywalny `git`; dotyczy to również IDE (JetBrains, VS Code) i nakładek graficznych, bo one uruchamiają gita pod spodem. Poza gwarancją są **własne implementacje protokołu** — JGit (Eclipse, Gerrit, część systemów CI) i narzędzia oparte na libgit2. Ryzyko jest konkretne: rejestrujemy filtr jako `filter.git-xcrypt.process`, a implementacja nieznająca protokołu długożyjącego może potraktować plik jako niefiltrowany i wpuścić plaintext do commita. Rozważano rejestrowanie równolegle `clean`/`smudge` jako siatki bezpieczeństwa (git przy ustawionym `process` i tak je ignoruje) i **odrzucono** — założenie o prawdziwym gicie jest jawne i zapisane, więc podtrzymywanie drugiej ścieżki tylko dla implementacji spoza zakresu byłoby kodem bez właściciela. Ograniczenie zapisane w `README.md` §Known limitations.
- **Ostrzeżenie przy pierwszym szyfrowaniu pliku.** Konstrukcja catch-all daje to niemal za darmo: filtr widzi każdy plik przechodzący przez `git add`, więc gdy plik jest szyfrowany po raz pierwszy, sprawdza jednym odczytem obiektu, czy ta sama ścieżka istnieje w `HEAD` jako jawna. Jeśli tak — ostrzeżenie na `stderr` z odesłaniem do `status`. To jedyny mechanizm uruchamiany automatycznie: hak `pre-commit` odpada (przełącznik „Run Git hooks" w JetBrains, `--no-verify` w terminalu, brak wersjonowania), a pełny skan historii w filtrze zatrzymywałby całe `git add`. **Nigdy kod niezerowy** — przy `required = true` przerwałby operację, a to jest ostrzeżenie, nie błąd.
- Znane ograniczenia, wszystkie w `README.md` §Known limitations: `git archive` eksportuje treść zaszyfrowaną (filtry nie są stosowane); submoduły mają własną konfigurację i wymagają osobnej inicjacji; klon bez `unlock` nie jest bezpieczny do zapisu.
- **`GIT_DIR` razem z `GIT_WORK_TREE` bez katalogu `.git` w drzewie (wzorzec „dotfiles") jest nieobsługiwane** — zmierzone: `init` odmawia z kodem `2`, bo odkrywanie repozytorium chodzi po katalogach. Fail-closed, więc bezpieczne; to samo dotyczy `core.worktree` w repozytorium gołym.

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

Bit w nagłówku usuwa oba: fakt normalizacji jest w pliku, więc smudge nie musi pytać o niego `.git-xcrypt` (o `eol=` pyta — patrz wyżej, to jest bezpieczne), a plik binarny nigdy nie dostanie konwersji, bo ma bit zerowy. Bit leży w AAD, więc jest uwierzytelniony. Determinizmu nie narusza — jego wartość wynika z deklaracji obowiązującej przy clean, a ta jest wersjonowana, więc identyczna na każdej maszynie.

**Deklaracja trybu należy do `.git-xcrypt`, nie do gita.** Skoro `-text` odbiera użytkownikowi atrybuty `text`/`eol` na plikach szyfrowanych, `.git-xcrypt` przejmuje **cały** słownik konwersji gita, nie jego podzbiór. Nie wymyślamy własnego modelu — odtwarzamy ten, który użytkownik zna z `.gitattributes`, z tą różnicą, że `eol=*` działa u nas na wyjściu smudge, a nie w gicie. Deklaracja jest wersjonowana, więc jest jednakowa na wszystkich maszynach — i to jest warunek, pod którym powyższy niezmiennik trzyma.

## Zmierzone zachowanie gita, które odtwarzamy

Pomiary z 2026-08-04, git 2.55, repozytoria tymczasowe. Cztery pliki, każdy z CRLF w środku, `core.autocrlf=true`:

| Treść pliku | Werdykt gita |
| --- | --- |
| czysty ASCII | tekst — znormalizowany |
| 2560 B z zakresu `0x80–0xFF`, bez NUL | **tekst** — znormalizowany |
| 2400 B z zakresu `0x01–0x08`, bez NUL | **binarny** — nietknięty |
| jeden bajt `0x00` na początku | binarny — nietknięty |

Reguła, w pełnej postaci odtworzonej w `src/eol.rs::looks_binary` i zamrożonej wraz z formatem:

1. **bajt NUL** gdziekolwiek → binarny;
2. **samotny `CR`** (bez następującego `LF`) → binarny. Reguła nieoczywista, ale konieczna: bez niej normalizacja nie jest domknięta na własnym wyjściu i plik po checkoucie wraca zmieniony;
3. **za dużo znaków sterujących**, dokładnie `(drukowalne >> 7) < niedrukowalne`, czyli **jeden niedrukowalny na 128 drukowalnych**. Zmierzone na git 2.55 przy `* text=auto`: 127 : 1 → binarny, 128 : 1 → tekst, 255 : 2 → binarny, 256 : 2 → tekst. Próg ma własny wektor testowy;
4. `BS`, `TAB`, `FF` i `ESC` liczą się jako drukowalne; **`DEL` (0x7f) jako niedrukowalny**, mimo że leży powyżej `0x20`;
5. bajty `≥ 0x80` liczą się jako **drukowalne**, dlatego UTF-8 jest poprawnie rozpoznawane jako tekst.

**Znane odstępstwo od gita:** końcowy bajt `SUB` (0x1A). Git odejmuje wtedy jeden `nonprintable` w `gather_stats`, my nie. To **jedyne** odstępstwo z 18 kształtów sprawdzonych wobec prawdziwego gita; usunięcie należy do elementu `S-08` roadmapy i musi zdążyć **przed** pierwszym wydaniem, bo reguła zamraża się razem z formatem.

**Korekta wcześniejszego zapisu w tym dokumencie:** heurystyka nie ogranicza się do „NUL w pierwszych 8000 bajtach". Zmierzone — NUL na offsecie 7 000, 9 000 i **1 000 000** za każdym razem daje werdykt binarny. Ścieżka konwersji CRLF skanuje **całą treść**. Limit 8000 bajtów należy do innej heurystyki: tej, którą `git diff` decyduje o `Binary files differ`.

**Detekcja gita zależy też od indeksu, nie tylko od treści.** Zmierzone: plik wprowadzony z CRLF przy `autocrlf=false`, potem `autocrlf=true` i modyfikacja → git **zostawia CRLF**; nowy plik w tym samym repozytorium przy `autocrlf=true` → normalizuje do LF. Stąd istnieje `git add --renormalize`. To jest rozstrzygający argument, żeby **nie** kopiować tego zachowania: nasza decyzja musi być czystą funkcją treści, inaczej ten sam plik dostaje różny werdykt zależnie od historii repozytorium — i determinizm pada.

## Składnia `.git-xcrypt`

```gitignore
# git-xcrypt — co jest szyfrowane i jak traktowane są końce linii.
# Wzorce: składnia .gitignore. Atrybuty: słownik .gitattributes.

# bez atrybutu = autorozpoznanie po treści
sekrety/
config/prod/
*.env
*.pem

# jawne wymuszenia tam, gdzie autorozpoznanie ma nie decydować
sekrety/*.sh         text eol=lf
sekrety/deploy.ps1   text eol=crlf
sekrety/klucz.p12    binary
/deploy/id_rsa       -text

# wyjątek — jawny mimo dopasowania wyżej
!sekrety/README.md
```

Atrybuty po wzorcu, oddzielone białymi znakami. Znaczenie odtwarza `.gitattributes` co do słowa:

| Atrybut | clean (przed szyfrowaniem) | smudge (po odszyfrowaniu) | bit 0 w `flags` |
| --- | --- | --- | --- |
| **brak** — równoważne `text=auto` | rozpoznaj po treści; jeśli tekst → `CRLF→LF` | wg `eol=` albo konfiguracji gita gdy bit `1`; verbatim gdy `0` | `1` albo `0` |
| `text=auto` | jw. — jawny zapis zachowania domyślnego | jw. | `1` albo `0` |
| `text` | `CRLF→LF` **zawsze**, bez pytania o treść | wg `eol=` albo konfiguracji gita | `1` |
| `-text` lub `binary` | bez konwersji | bajt w bajt to, co zapisano | `0` |
| `eol=lf` | — | zawsze LF | bez wpływu |
| `eol=crlf` | — | zawsze CRLF | bez wpływu |
| `eol=native` | — | LF na Unix, CRLF na Windows | bez wpływu |
| brak `eol=` | — | tabela konfiguracji gita powyżej | bez wpływu |

**Zachowanie domyślne to `text=auto`** — brak atrybutu znaczy „rozpoznaj sam, czy konwersja jest potrzebna", tak jak w gicie. Nie ma dyrektywy ustawiającej tryb domyślny dla całego pliku: wartość domyślna jest jedna, wpisana w narzędzie. Nie bierzemy jej z `core.autocrlf`, mimo że git tak robi — konfiguracja nie jest wersjonowana, a czytanie jej na ścieżce clean dałoby różny plaintext na różnych maszynach.

**Rozstrzyganie, gdy do ścieżki pasuje kilka linii** — dwie niezależne osie, dokładnie jak w gicie rozdzielonym na `.gitignore` i `.gitattributes`:

| Oś | Reguła |
| --- | --- |
| **selekcja** — czy szyfrować | ostatnie dopasowanie wygrywa; `!` wyłącza |
| **atrybuty** — jak konwertować | późniejsza linia nadpisuje **tylko te atrybuty, które wymienia**; linia bez atrybutów niczego nie zeruje; nic nieustawione → `text=auto` |

Sloty są dwa i niezależne: `text` / `-text` / `binary` / `text=auto` to jeden, `eol=` drugi. Dzięki temu szeroki wzorzec selekcji (`sekrety/`) dopisany pod wąską deklaracją (`*.env text`) nie kasuje jej po cichu.

- **`binary`** jest synonimem `-text`, dodatkowo wyłącza `diff=git-xcrypt` w wygenerowanej linii kosmetycznej — tak jak makro `binary` w gicie oznacza `-text -diff`.
- **`eol=` przy `-text` jest bezskuteczne** — odtwarzamy zmierzone „`-text` bije `eol`". Kombinacja jest bezsensowna, ale nie niebezpieczna: ostrzeżenie na `stderr`, bez przerywania operacji.
- **Atrybuty na linii z negacją to błąd** — plik nie jest szyfrowany, więc nie ma czego konwertować. Fail closed.
- **`text=auto` jest jedynym atrybutem zależnym od treści.** Używa reguły zmierzonej wyżej — NUL albo nadmiar znaków sterujących poniżej `0x20` — ale **wyłącznie jako funkcji treści**, nigdy z zaglądaniem do indeksu, w odróżnieniu od gita. Skoro jest zachowaniem domyślnym, decyduje o ciphertexcie większości plików: reguła jest **zamrożona wraz z formatem** i ma **własne wektory testowe**, obok wektorów formatu i wektorów z RFC 5297. Konsekwencja tej semantyki, identyczna jak w gicie: plik, który przestaje być tekstem, przestaje być normalizowany, więc w różnicy odszyfrowanej treści widać wtedy zmianę wszystkich linii doklejoną do właściwej edycji. Determinizmu to nie narusza i treści nie uszkadza.
- **`eol=` celowo nie trafia do nagłówka.** Gdyby trafiło, zmiana deklaracji z `eol=lf` na `eol=crlf` nie zadziałałaby na istniejące pliki aż do ich ponownego dodania. Trzymamy w nagłówku wyłącznie fakt „normalizowano", bo tylko on jest niebezpieczny przy rozjeździe. Wybór końca linii przy smudge jest samonaprawialny: gdy padnie źle, następny clean i tak normalizuje z powrotem do LF, ciphertext wychodzi ten sam, a `git status` zostaje czysty. Pliki binarne mają bit `0` i są zapisywane verbatim, więc nie dotyczy ich to w ogóle.
- **Nieznany atrybut to błąd**, nie ostrzeżenie — fail closed, ta sama zasada co przy nieznanym `suite` i nieznanym bicie `flags`.
- **Poza zakresem:** `working-tree-encoding` (konwersja kodowania znaków, np. UTF-16). Git to potrafi, my nie — zapisane w `README.md` §Known limitations.

**Konfigurację czytamy biblioteką, nie procesem potomnym.** `gix-config` (gitoxide) daje precedencję system/global/repo/worktree wraz z `include`, kompiluje się do środka binarki i nie łamie wymogu samowystarczalności z „Założeń technicznych". Wywoływanie `git config` odpada z powodu samowystarczalności — argument o N spawnach był prawdziwy dla prototypu z procesem na plik i przy filtrze długożyjącym już nie obowiązuje, ale wniosek zostaje. Pozostaje jedna binarka `git-xcrypt` w dwóch trybach rejestrowanych przez `init` (`process` i `diff`; reszta komend wywoływana przez użytkownika); żadnego osobnego programu pomocniczego ani demona.

**Trzy zmierzone ograniczenia `gix-config`, świadomie przyjęte** (wszystkie dotyczą wyłącznie EOL, więc są samonaprawialne — następny clean i tak normalizuje do LF):

- `GIT_CONFIG_PARAMETERS`, czyli `git -c core.autocrlf=…`, jest dla filtra **niewidoczne** (`gix-config` czyta `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n`);
- `includeIf` w konfiguracji **globalnej** nie jest rozwijane;
- w podłączonym worktree czytany jest `config.worktree` **głównego** checkoutu, nie własny.

Determinizmu żadne z nich nie łamie, bo ścieżka `clean` konfiguracji nie czyta w ogóle.

**Świadomie przyjęte ograniczenie:** plik o mieszanych końcach linii nie przetrwa round-tripu — normalizacja jest stratna, więc po `unlock` taki plik wróci inny niż był i `git status` pokaże zmianę. Git broni się przed tym przez `core.safecrlf`; czy odtwarzamy to ostrzeżenie, jest otwarte.

# Bezpieczeństwo i świadome ograniczenia

Wszystkie poniższe są **akceptowanymi kompromisami** konstrukcji, nie błędami:

- Wyciekają **metadane**: nazwy plików, ścieżki, rozmiary, daty commitów i fakt, że plik się zmienił. Rozmiar przecieka **dokładnie**, a nie w przybliżeniu: SIV szyfruje trybem CTR, więc `rozmiar bloba = 38 + rozmiar treści`, co do bajta.
- Szyfrowanie deterministyczne ujawnia, że dwa pliki mają identyczną treść, oraz że plik wrócił do poprzedniej wersji.
- **Największe realne ryzyko: sekret zacommitowany zanim wzorzec trafił do konfiguracji.** Zostaje w historii w postaci jawnej na zawsze. Przeciwdziałanie: `git-xcrypt status` skanuje całą osiągalną historię i wskazuje takie pliki, a dokumentacja opisuje procedurę czyszczenia historii. **Kolejność w tej procedurze jest wiążąca: najpierw rotacja sekretu, potem historia.** Przepisanie historii czyści repozytorium, ale nie cofa wycieku — sekret zostaje w forkach, cache'ach, logach CI i w każdym klonie, który już powstał.
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
- CI na wszystkich trzech platformach — **istnieje**, `.github/workflows/ci.yml`: `cargo test --all-targets` na ubuntu/macOS/Windows, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo audit` (`rustsec/audit-check`), `cargo deny check licenses advisories sources bans` z polityką w `deny.toml`, plus zadanie `msrv` budujące i testujące na zadeklarowanym `rust-version`. Polityka licencyjna pilnuje, by copyleft nie wszedł bocznymi drzwiami z zależnością i nie unieważnił wyboru `MIT OR Apache-2.0`; jedyne przyjęte świadomie odstępstwo od pary MIT/Apache to `Zlib` (`zlib-rs` przez `gix-zlib`) i `BSD-3-Clause` (`subtle`).
- Scenariusz regresyjny na Windows z włączonym `core.autocrlf=true`.

# Kryteria akceptacji

Projekt uznajemy za działający, gdy poniższy scenariusz przechodzi automatycznie na trzech platformach. **Stan na 2026-08-04:** scenariusz jest zapisany jako pojedynczy test `tests/acceptance.rs::the_six_step_acceptance_scenario_passes_end_to_end` — z prawdziwym `git push` do repozytorium gołego i sprawdzeniem blobów **tam**, nie w repozytorium źródłowym — i przechodzi. Na trzech platformach uruchamia go CI; do tego przebiegu był mierzony wyłącznie na macOS.

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
5. **Próg rozmiaru pliku, powyżej którego przechodzimy na buforowanie dyskowe zamiast RAM.** Zaostrzone 2026-08-04: `aes-siv` 0.7 ma API jednorazowe, więc dziś każdy plik trafia do RAM w całości. Rozwiązania są dwa i oba mieszczą się w formacie: buforowanie na dysku albo nowy `suite` z trybem blokowym. Punkt odniesienia z przeglądu końcowego: plik 64 MB przechodzi pełny round-trip przez prawdziwego gita bez problemu, więc próg — gdy powstanie — będzie znacznie wyżej, niż sugerowała pierwsza wersja tego pytania.
6. Które komendy z oryginału poza listą MVP faktycznie chcemy odtworzyć.
7. ~~**Zachowanie domyślne przy braku deklaracji EOL w `.git-xcrypt`.**~~ Rozstrzygnięte 2026-08-04: **`text=auto`** — brak atrybutu znaczy „rozpoznaj po treści, czy konwersja jest potrzebna", tak jak w gicie. Bez dyrektywy ustawiającej tryb domyślny; wartość jest jedna i wpisana w narzędzie, bo `core.autocrlf` nie jest wersjonowane. Patrz „Końce linii" → „Składnia `.git-xcrypt`".
8. **Czy odtwarzamy ostrzeżenie `core.safecrlf`** dla plików o mieszanych końcach linii, które nie przetrwają round-tripu. Dotyczy ścieżek zadeklarowanych jako `text` oraz rozpoznanych jako tekst przez `text=auto`, czyli przy domyślnym trybie — większości plików. Propozycja: ostrzeżenie na `stderr`, bez blokowania operacji.
9. ~~**Kod wyjścia `5` jest przeciążony.**~~ Rozstrzygnięte 2026-08-04: **nowy kod `6` — „nie dało się ustalić"**, a `5` znaczy odtąd wyłącznie ekspozycję. Tabela kodów została świadomie rozszerzona mimo zamrożenia, bo koszt jest zerowy przed pierwszym wydaniem, a alternatywa (degradacja płytkiego klonu do noty) chowałaby „nie wiem" pod kodem `0`. Szczegóły i precedencja „znalezisko wygrywa z niewiadomą": „Integracja z git" → kody wyjścia.
10. **Czy `status` ma rozwiązywać atrybuty gita, zamiast je nazywać.** Dziś raport wypisuje każdy `.gitattributes` w drzewie, `info/attributes` i `core.attributesFile`, które dotykają `filter`, i odsyła do `git check-attr`. Pełna odpowiedź na „czy git uruchomi filtr dla tej ścieżki" wymaga własnej implementacji dopasowania atrybutów, praktycznie nowej zależności `gix-attributes`.
11. **Kolizja kodu `1` przy `lock` i `sync --check`.** Przerwanie przez użytkownika, błąd argumentów i porażka zapisu w połowie dają przy `lock` ten sam kod; `sync --check` używa `1` dla „sekcja nieaktualna". Rozróżnienie wymaga ruszenia zamrożonej tabeli.
12. **Skracanie nazwy pliku tymczasowego przy nazwach ≥ 224 B** oznacza, że residuum po zabitym przebiegu na takim pliku może nie zostać zamiecione przez `lock`. Jeśli obietnica „po `lock` nie zostaje żaden plaintext" ma być bezwarunkowa, potrzebny jest inny schemat nazw — np. rejestr residuum w `.git/`.
13. **Semantyka wzorców wobec `core.ignorecase` i normalizacji Unicode w nazwach plików.** Nie sprawdzone i nie rozstrzygnięte; ma znaczenie na macOS i Windows, gdzie system plików bywa nieczuły na wielkość liter albo normalizuje nazwy.
14. **Podpisywanie artefaktów wydania.** `release.yml` publikuje sumy SHA-256, ale nie podpisuje niczego. PRD FR-011 notuje kontrargument, że niepodpisana binarka narzędzia kryptograficznego to nowy wektor zaufania; do rozstrzygnięcia przed pierwszym publicznym wydaniem.
