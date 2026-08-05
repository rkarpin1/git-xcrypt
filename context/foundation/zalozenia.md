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
  - Nazwa zawierająca spację domyka się **cudzysłowem**, tak jak w `.gitattributes` (`"moje sekrety/"`, negacja `!"moje sekrety/README.md"`). Backslash nie jest już ucieczką białego znaku — od 2026-08-05 znaczy wyłącznie to, co znaczy w globie. Powód, migracja i siatka na stare pliki: „Końce linii (LF/CRLF)" → „Spacja w nazwie".
- Pozostałe komendy `git-xcrypt` mają odpowiadać projektom źródłowym co do nazwy i zachowania, ale każda wymaga oddzielnej dyskusji i potwierdzenia przed implementacją.

# Zakres MVP / poza zakresem

**W zakresie v0.1:**

- `git-xcrypt init` — generuje klucz repozytorium, rejestruje filtry w `.git/config` (w tym `filter.git-xcrypt.process` i `required = true`), tworzy `.git-xcrypt` (jeśli brak) i wpisuje do `.gitattributes` statyczną linię catch-all.
- `git-xcrypt status` — rozstrzygnięte 2026-08-04, cztery zadania:
  - **kompletność konfiguracji** — czy `filter.git-xcrypt.*` jest w `.git/config`. Bez tego klon, w którym nie uruchomiono `init`/`unlock`, przepuszcza treść mimo linii catch-all w `.gitattributes`.
  - **skan całej osiągalnej historii** — czy pliki dziś szyfrowane występowały kiedyś w repozytorium w postaci jawnej. Sprawdzenie płytkie odpada: sekret zacommitowany przed konfiguracją albo później usunięty z `HEAD` jest w `HEAD` niewidoczny, a nadal leży w historii i nadal jest u hostingodawcy. Skan nie wymaga deszyfrowania — wystarczy sprawdzić 11 bajtów magic na początku każdego bloba, którego ścieżka pasuje do wzorca, więc koszt zależy od liczby obiektów, nie od ich rozmiaru.
  - **`--fix` dla naprawy bezpiecznej** — pliki pasujące do wzorca, a leżące jawnie w `HEAD` lub indeksie, zostają ponownie dodane, więc od następnego commita są szyfrowane. Operacja lokalna, bez przepisywania historii. Flaga siedzi przy `status`, bo diagnoza i naprawa dzielą całą analizę.
  - **sekcja `undetermined`** — dodana przy implementacji i nośna dla werdyktu: „nie dało się ustalić" nigdy nie może być raportowane jako „nic złego się nie dzieje". Trafiają tu klon płytki i częściowy, split index, nieczytelny indeks i niewyliczalny magazyn referencji. Od 2026-08-04 ma **własny kod wyjścia `6`**, patrz „Integracja z git" → kody wyjścia. **Korekta z 2026-08-05:** brak `.git-xcrypt` **nie** należy już do tej listy — to luka konfiguracji, czyli kod `2`. Sam skan, którego wtedy nie da się przeprowadzić, nadal ląduje w `undetermined` i jest wypisywany.
  - **luka konfiguracji ma kod `2` — rozstrzygnięte 2026-08-05.** Nowa precedencja werdyktu: **`2` (konfiguracja) > `5` (ekspozycja) > `6` (nie ustalono) > `0` (czysto)**. Uzasadnienie właściciela: **bez poprawnej konfiguracji dane w repozytorium są nic nie warte** — checkoutu, w którym git nie uruchamia filtra, nie da się uznać za czysty, nie da się przewidzieć, co zapisze jako następny, i przede wszystkim nie da się naprawić działaniem na tym, co raport mówi o jego danych. Operator dostaje więc jedną naprawę, która nadaje sens reszcie, i pyta ponownie. Powód konkretny: repozytorium, które **nigdy nie uruchomiło `init`**, dostawało `5`, czyli „znaleziono ekspozycję, rotuj sekret" — a nie ma tam czego rotować. Kodu nie dokładamy: `2` jest w zamrożonej tabeli i znaczy „błąd konfiguracji lub konfliktu stanu", dokładnie tak, jak używają go `init` i `lock`.
  - **`2` niczego nie ukrywa.** Raport jest niezależny od kodu wyjścia: repozytorium z wyciekiem w historii **i** zepsutą konfiguracją kończy `2`, ale nadal wypisuje sekcję `leaked in history`, nazywa ścieżki i drukuje procedurę zaczynającą się od rotacji sekretu — linia `VERDICT:` mówi wprost `Also found, and NOT cancelled by the above`. Po naprawie konfiguracji to samo repozytorium kończy `5`. Informacja nie ginie, zmienia się wyłącznie kolejność pracy. Pilnują tego trzy testy: `commands::status::tests::configuration_outranks_both_other_answers_and_conceals_neither`, `a_missing_declaration_is_a_configuration_gap_that_still_admits_it_checked_nothing` oraz sekcja „Configuration before data" w `tests/odd_repositories.rs`.
  - Przy znalezisku kod wyjścia `5`, przy „nie dało się ustalić" `6`, przy luce konfiguracji `2` — pozwala wpiąć komendę w CI jako bramkę i odróżnia ekspozycję od błędu narzędzia, od niezbadanego checkoutu i od checkoutu, który niczego nie egzekwuje. **Bramka CI ma traktować `2`, `5` i `6` jako porażkę.** Pełny skan historii wymaga pełnego klonu (`fetch-depth: 0` w `actions/checkout`); bez tego `status` uczciwie kończy `6`.
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
- **Sprawdzenia powtarzane *po* odpowiedzi na pytanie — domknięte 2026-08-05.** Prompt jest nieograniczonym czasowo oknem w środku komendy, która za chwilę skasuje klucz, więc wszystko, co `lock` udowodnił **przed** pytaniem, trzeba udowodnić jeszcze raz po nim. Dotąd powtarzany był wyłącznie przegląd drzewa roboczego (plik utworzony w trakcie promptu); lista innych checkoutów — nie. **Zmierzone na git 2.55:** `git worktree add` uruchomione 1,5 s po starcie promptu, `yes` wpisane w 3. sekundzie — `lock` skończył **kodem 0**, ogłosił „1 file(s) are now encrypted and key … has been deleted", a nowy checkout został z `AWS_SECRET=hunter2` jawnie i bez klucza, którym dałoby się go zamknąć. `git worktree add` wypisuje nowe drzewo **przez filtr smudge**, więc każdy zadeklarowany plik ląduje tam odszyfrowany, a przegląd tego nie widzi, bo chodzi po własnym drzewie. Wczesne wywołanie zostaje — dzięki niemu repozytorium z podłączonym checkoutem nie dostaje w ogóle tego strasznego pytania.

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
- **Kopia zapasowa klucza jest obowiązkiem użytkownika — rozstrzygnięte 2026-08-04.** W v0.1 nie powstaje żaden mechanizm kopii: ani automatyczny, ani przypomnienie w `init` (rozważone i odrzucone — odpowiedzią jest dokumentacja, nie kolejny komunikat). Ponieważ `.git/` nie jest wersjonowane ani pushowane, plik klucza jest **jedyną** kopią, a jego utrata to trwała utrata całej historii sekretów, we wszystkich commitach i klonach. `README.md` ma na to osobną sekcję („The key file is the only copy — back it up yourself") i wpis w §Known limitations: kopię robi `export-key`, i wskazane jest, gdzie ta kopia leżeć nie może. Cztery istniejące zabezpieczenia (`export-key` odmawiający zapisu w repozytorium, potwierdzenie `yes` przy `lock`, `key_id` zamiast klucza, odmowa przy niezacommitowanych zmianach i przy innych worktree) są progami zwalniającymi, nie kopią. PRD Open Question 2 zostaje otwarte na przyszłość.
- **Uprawnienia pliku klucza: `0600` na systemach uniksowych, a na Windows żadne — korekta z 2026-08-05.** Poprzedni zapis („na Windows odpowiednie ACL ograniczone do właściciela") pochodzi z pierwszego commita ze scaffoldem i opisywał zamiar, którego nigdy nie zaimplementowano. Sprawdzone w kodzie, nie zgadnięte: `atomic::create_temporary` ustawia tryb wyłącznie w gałęzi `#[cfg(unix)]`, a `atomic::replace` w trybie `OwnerOnly` świadomie nie dziedziczy uprawnień celu — więc poza uniksem plik klucza dostaje ACL dziedziczone z katalogu, w którym powstaje, i nic go nie zawęża. Dla klucza repozytorium w `.git/` to dokładnie tyle ochrony, ile git daje `.git/config`; dla `export-key` decyduje katalog wskazany przez użytkownika, więc kopia w katalogu czytelnym dla innych kont jest czytelna dla innych kont. Zapisane wprost w `README.md` — w sekcji o kopii klucza i w §Known limitations — żeby użytkownik Windows wybierał katalog świadomie, zamiast polegać na `0600`, którego tam nie ma. **Rozstrzygnięte 2026-08-05: v0.1 tego nie domyka** — natywne ACL wymagałoby bloku `unsafe`, a reguła „zero `unsafe`" ma pozostać bezwyjątkowa. Uzasadnienie i koszt: „Otwarte decyzje" poz. 15.
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
- **Kody wyjścia — rozstrzygnięte 2026-08-04, rozszerzone 2026-08-04 o kod `6`, doprecyzowane 2026-08-05 co do znaczenia `2`:** `0` sukces, `1` błąd użycia lub nieznany, `2` błąd konfiguracji lub konfliktu stanu (nie jest to repozytorium git, konflikt przy `init`, brudny katalog roboczy przy `lock`, **a od 2026-08-05 także luka konfiguracji wykryta przez `status`**), `3` brak klucza, `4` błąd formatu (magic, `key_id`, nieznany bit `flags`, porażka tagu), `5` znaleziono ekspozycję (`status` wykrył jawne wersje w historii albo pliki niezaszyfrowane mimo wzorca), `6` **nie dało się ustalić** (`status` nie mógł odpowiedzieć na pytanie).
  - **Rozszerzenie tabeli 2026-08-04 — świadome złamanie zamrożenia, przed pierwszym wydaniem.** Powód jest zmierzony: `5` niósł dotąd obie odpowiedzi naraz, więc **zdrowy `git clone --depth 1` kończył piątką**, a `actions/checkout` klonuje płytko, dopóki nie dostanie `fetch-depth: 0` — czyli domyślna konfiguracja CI nie przechodziła bramki, którą ta komenda ma być. Bramka, która alarmuje na własnej konfiguracji domyślnej, zostaje wyłączona. Odrzucona alternatywa: zdegradowanie płytkiego i częściowego klonu do noty — to samo „nie dało się ustalić" trafiłoby wtedy do kodu `0`, czyli dokładnie do odpowiedzi, której `status` nigdy nie może udzielić. Koszt rozszerzenia jest dziś zerowy (nie istnieje żaden odbiorca poza tym repozytorium), po wydaniu byłby zmianą łamiącą.
  - **`5` znaczy odtąd wyłącznie ekspozycję**, a `6` — klon płytki, klon częściowy, podzielony indeks, indeks nieczytelny, magazyn referencji, którego nie da się wyliczyć, referencja nierozwiązywalna. **Znalezisko wygrywa z niewiadomą**: przebieg, który jednocześnie znalazł wyciek i nie zdołał odczytać indeksu, kończy `5`. Kierunek odwrotny osłabiałby bramkę po cichu. (Brak `.git-xcrypt` był na tej liście do 2026-08-05 i należy odtąd do `2` — patrz punkt niżej.)
  - **Precedencja werdyktu `status` — rozstrzygnięte 2026-08-05: `2` (konfiguracja) > `5` (ekspozycja) > `6` (nie ustalono) > `0` (czysto).** Luka konfiguracji — niezarejestrowany filtr, `required` nieustawione na prawdę, brak linii catch-all, atrybut `filter` rozwiązywany przez gita na coś innego, konwersja końców linii na ciphertexcie, nieskomitowany plik bootstrapowy, brak `.git-xcrypt` — kończy **kodem `2`**. Uzasadnienie właściciela: **bez poprawnej konfiguracji dane w repozytorium są nic nie warte**. Powód zmierzony: repozytorium, które nigdy nie uruchomiło `init`, dostawało dotąd `5`, czyli „znaleziono ekspozycję" — komunikat każący rotować sekret w miejscu, gdzie nie ma czego rotować, przy jednoczesnym zepchnięciu jedynej prawdziwej usterki (git nie uruchamia filtra) do rangi szczegółu.
    - To **odwraca** regułę „znalezisko wygrywa z niewiadomą" w dokładnie jednym punkcie: luka konfiguracji wygrywa teraz z jednym i drugim. Relacja `5` > `6` zostaje bez zmian.
    - **Nowego kodu nie dokładamy.** `2` jest w zamrożonej tabeli i znaczy „błąd konfiguracji lub konfliktu stanu"; używamy go zgodnie z tą definicją, tak jak używają go `init` (ślady konfiguracji bez klucza) i `lock` (brudne drzewo robocze).
    - **Kod `2` nie ukrywa ani jednej sekcji raportu** — to wiążący wymóg tej zmiany, nie skutek uboczny. Repozytorium z wyciekiem w historii i zepsutą konfiguracją kończy `2`, a raport nadal wypisuje `leaked in history`, nazywa ścieżki i drukuje procedurę „najpierw rotacja". Linia `VERDICT:` mówi wprost, ile jest luk konfiguracji, i dokleja `Also found, and NOT cancelled by the above`. Po naprawie konfiguracji to samo repozytorium kończy `5`. Operator zmienia kolejność pracy, nie traci informacji.
    - **Brak `.git-xcrypt` to jedyny przypadek z wczesnym powrotem**: bez deklaracji nie da się ustalić, które ścieżki miały być szyfrowane, więc ani indeks, ani historia nie są skanowane. Stan jest luką konfiguracji (kod `2`), a **nieprzeprowadzona część trafia do `undetermined`** i jest wypisywana zdaniem `history was NOT scanned`. Milczenie byłoby tu gorsze niż zły kod. Nic nie jest przy tym zapisywane jawnie — ścieżka clean odmawia na tym samym stanie — więc komunikat sekcji `setup` mówi to wprost i nie każe rotować sekretu.
  - Komunikat rozstrzyga to samo bez czytania kodu: werdykt `undetermined` mówi wprost `NOTHING WAS FOUND, and nothing is ruled out either`, bo odpowiedzi wymagają różnych reakcji operatora — `2` mówi „napraw konfigurację i zapytaj ponownie", `5` mówi „rotuj sekret", `6` mówi „napraw checkout i zapytaj ponownie".
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
- **Odmowa, gdy git przekonwertowałby ciphertext — rozstrzygnięte 2026-08-05.** Drugi mechanizm uruchamiany automatycznie na ścieżce `clean`, i w przeciwieństwie do ostrzeżenia wyżej **przerywa operację**. Filtr, zanim odda zaszyfrowane bajty, pyta stos atrybutów gita (`gitattributes::AttributeResolver`, ten sam, którego używa `status`), czy git przekonwertuje jego wyjście. Jeśli tak — `status=error`, czyli przy `required = true` `git add` pada, blob nie powstaje i **plik nie ginie**.
  - **Dlaczego to w ogóle wykonalne:** kolejność gita to `clean` → zapis bloba → konwersja CRLF. W momencie, w którym filtr odpowiada, nic jeszcze nie jest zniszczone. Zmierzone przed decyzją (git 2.55, 2 MB, `.git-xcrypt` = `sekrety/  binary`, dopisana linia `sekrety/** text`): `git add` kod 0, `git commit` kod 0, blob 2 097 158 B zamiast 2 097 190 B, a `git checkout` kończy się `authentication failed` i **plikiem, którego nie ma**. Ten sam pomiar dla drugiego kształtu (`sekrety/** !text` plus `sekrety/** eol=lf`): blob 2 097 151 B i ten sam koniec.
  - **Predykat to dokładnie tabela z „Rozstrzyganie atrybutów przez `status`", ani szerszy:** groźne są `text` rozstrzygnięte na `set` oraz `text` `unspecified` z gołym `eol=lf|crlf`. `-text`, `binary`, `text=auto`, obcy `filter=lfs` na innej ścieżce i dowolne `core.autocrlf` są zmierzone jako obojętne. Przy `required = true` fałszywa odmowa blokuje **każdą** operację gita w repozytorium, więc szerokość predykatu jest tu samodzielnym ryzykiem.
  - **Pytanie zadawane wyłącznie o ścieżkę, która faktycznie staje się ciphertextem.** Plik przechowywany jawnie jest gita do konwertowania i odmowa nad nim byłaby awarią w zdrowym repozytorium. Bramka siedzi więc na `decide(path).encrypt` i na liście nigdy-nie-szyfrowanych.
  - **Dlaczego nie wystarczał `status`:** rozstrzyga wyłącznie ścieżki, które indeks już zna, więc na *nowym* pliku kończy kodem 0, a pierwsze ostrzeżenie przychodzi przy checkoucie, czyli gdy pliku już nie ma. Zmierzone.
  - **Koszt:** stos atrybutów budowany leniwie i raz na proces (chodzenie po drzewie roboczym za każdym `.gitattributes`), tak samo jak `Context::head`. Zmierzone, `git add -A` na 2000 plikach ze 200 zadeklarowanymi w 201 katalogach, build `--release`, mediana z pięciu przebiegów: **135 ms → 137 ms**. Repozytorium, które niczego nie deklaruje, nie płaci nic — resolver nie powstaje.
  - **Determinizm nietknięty:** odmowa nie zmienia ani jednego bajtu ciphertextu. Reguła „clean nie czyta konfiguracji gita" dotyczy tego, *co* szyfrujemy; to jest pytanie, *czy w ogóle* oddawać wynik.
  - Komunikat na `stderr` podaje ścieżkę, plik i numer linii, która wygrywa z sekcją zarządzaną, oraz co zrobić. Testy: `tests/attributes.rs`, obie strony — odmowa przy obu groźnych kształtach i brak odmowy przy obojętnych.
- **Diagnoza na ścieżce `smudge`, gdy git przekonwertował ciphertext — rozstrzygnięte 2026-08-05.** Drugi koniec tej samej pomyłki, dla repozytorium, w którym groźna linia pojawiła się **po** commicie: odmowa z `clean` nie ma już czego zatrzymać, blob jest zdrowy, a checkout i tak pada. Zmienia się **wyłącznie komunikat** — werdykt zostaje, bo porażka tagu jest tu poprawna: treść, którą smudge dostał, naprawdę nie jest tym, co zaszyfrowano, a wydanie jej łamałoby regułę „porażka tagu to błąd, nie ostrzeżenie". Nic nie trafia do drzewa roboczego, kod wyjścia bez zmian.
  - **Dlaczego to jest problem:** kolejność gita przy checkoucie to blob → konwersja gita → `smudge`, więc tag dostaje bajty, których nigdy nie zapisano. Dotychczasowe `authentication failed; the file has been altered` czyta się jako „repozytorium jest uszkodzone, dane przepadły" — nad plikiem, który jest cały co do bajta. Zmierzone (git 2.55, 2026-08-05, plik 512 KB, blob 524 326 B, dopisana linia `sekrety/** text`, `core.autocrlf=true`, czyli domyślna w Git for Windows): checkout pada, pliku w drzewie nie ma, **blob nietknięty**. Naprawą jest usunięcie tamtej linii, nie rotacja i nie odzyskiwanie danych.
  - **Predykat wymaga trzech rzeczy naraz** i jest liczony **dopiero po porażce tagu** — ścieżka szczęśliwa nie płaci nic, a to jest tu warunek konieczny, bo smudge biegnie przy każdym checkoucie i przy `git clone` dla każdego pliku:
    1. **odcisk konwersji w treści** (najtańsze, więc pytane pierwsze): ani jednego samotnego `LF` i przynajmniej jeden `CRLF`. `crlf_to_worktree` zamienia każdy samotny `LF` na `CRLF` i nie rusza istniejących, więc jego wyjście z definicji nie zawiera samotnego `LF`; brak `CRLF` znaczy, że nie było czego rozwijać, czyli bajty są blobem i wina leży po stronie pliku. Ten sam warunek wyklucza uszkodzenie z kierunku *wejściowego* — tam git zjada `CR`, więc blob zostaje pełen samotnych `LF`. Zmierzone filtrem kopiującym swoje `stdin`: blob 4118 B z 18 samotnymi `LF` i zerem `CRLF` dociera jako 4136 B z 18 `CRLF` i zerem samotnych `LF`;
    2. **stos atrybutów gita faktycznie konwertuje tę ścieżkę** — ten sam `AttributeResolver`, ta sama `Culprit` z plikiem, numerem linii i przypisaniem, co po stronie `clean`;
    3. **kierunek checkoutu na tej maszynie to `CRLF`**. To **nie jest** ta sama tabela co przy `clean`: `text eol=lf` konwertuje na wejściu i wypisuje bajty nietknięte, a `core.eol` ma głos dopiero, gdy jakaś linia ustawi `text`. Zmierzone na git 2.55, blob z samotnymi `LF`: `text`+`autocrlf=true` → rozwija; `text`+`autocrlf=false`+`core.eol=crlf` → rozwija; `text`+`autocrlf=input` → nie; `text eol=lf` → nie; `eol=crlf` bez `text` → rozwija, ale nie na naszych ścieżkach, bo `-text` z sekcji zarządzanej wygrywa z `eol`; samo `autocrlf=true` bez `text` → nie, bo działa detekcja binarna i widzi wiodący NUL.
  - **Czego predykat świadomie nie dowodzi:** że zapisany blob się odszyfruje. Nie da się — rozwinięcie nie jest odwracalne, bo `CRLF` na wyjściu mógł powstać zarówno z zapisanego `CRLF`, jak i z zapisanego samotnego `LF`. Zostaje jeden przypadek resztkowy: ciphertext uszkodzony przez tę samą konwersję na *wejściu*, buildem starszym niż 2026-08-05, w repozytorium wciąż niosącym tę linię. Trzyma go uczciwym to, że żadne zdanie komunikatu nie jest tam fałszywe (checkout wyłącznie czyta) oraz **samonaprawialność stanu**: po usunięciu linii predykat przestaje działać i najbliższy checkout mówi `the file has been altered` — użytkownik nigdy nie zostaje z fałszywym „wszystko w porządku".
  - **Komunikat niesie trzy rzeczy, w tej kolejności:** że nic nie jest stracone (zdanie najważniejsze, bo wszystko, co użytkownik widzi, mówi coś przeciwnego), która linia w którym pliku to zrobiła, i co zrobić — usunąć albo zawęzić tamtą linię, uruchomić `sync`, powtórzyć checkout. Na końcu zdanie weryfikujące: jeśli po usunięciu linii nadal pada, uszkodzony jest sam ciphertext i powie o tym `status`.
  - **Koszt zmierzony:** checkout 2000 plików (1000 zaszyfrowanych, 1000 jawnych), build `--release`, sześć przebiegów naprzemiennie tą samą binarką przed i po, na tym samym repozytorium: mediana **178 ms → 178 ms**. Ścieżka bez porażki tagu nie wykonuje ani jednej dodatkowej instrukcji poza `map_err` nad `Ok`.
  - Testy: `tests/attributes.rs`, obie strony — konwersja jako przyczyna daje nowy komunikat, a prawdziwie zmieniony ciphertext, ciphertext bez ani jednego `LF`, ciphertext już rozwinięty pod `text eol=lf` i plik obcego klucza dostają komunikat dotychczasowy. Ta druga strona waży więcej: fałszywe „to tylko konfiguracja" nad repozytorium, które naprawdę coś straciło, byłoby gorsze niż komunikat, który zastępuje.
- Znane ograniczenia, wszystkie w `README.md` §Known limitations: `git archive` eksportuje treść zaszyfrowaną (filtry nie są stosowane); submoduły mają własną konfigurację i wymagają osobnej inicjacji; klon bez `unlock` nie jest bezpieczny do zapisu.
- **`GIT_DIR` razem z `GIT_WORK_TREE` bez katalogu `.git` w drzewie (wzorzec „dotfiles") jest nieobsługiwane** — zmierzone: `init` odmawia z kodem `2`, bo odkrywanie repozytorium chodzi po katalogach. Fail-closed, więc bezpieczne; to samo dotyczy `core.worktree` w repozytorium gołym.


## Rozstrzyganie atrybutów przez `status` — rozstrzygnięte 2026-08-04, rozszerzone 2026-08-05

`status` nie wypisuje już podejrzanych linii `.gitattributes` — **odtwarza stos atrybutów gita i pyta o faktyczną wartość `filter` oraz `text`/`eol`** dla każdej zadeklarowanej ścieżki w indeksie, dokładnie tak, jak odpowiadają `git check-attr filter` i `git check-attr text eol`.

Powód: linia zarządzana `* filter=git-xcrypt` jest jedną z wielu, a git bierze **ostatnie** dopasowanie. Linia pod sekcją zarządzaną, `.gitattributes` w podkatalogu albo `$GIT_DIR/info/attributes` (niewersjonowany, o najwyższym priorytecie) wyłączają filtr dla ścieżek, które to narzędzie uważa za chronione. Zmierzone na git 2.55: `git check-attr filter -- secrets/db.env` odpowiada `unset`, kolejny `git add` zapisuje plaintext z kodem `0`, a każde inne sprawdzenie w tej komendzie przechodzi. Do 2026-08-04 była to **nota**, a nota nie zapala bramki CI — czyli ostatnia droga do zielonego raportu na repozytorium, które faktycznie nie szyfruje.

- **Odtworzony porządek priorytetów** (od najniższego): wbudowane makro `[attr]binary`, `core.attributesFile`, `.gitattributes` z korzenia i kolejnych katalogów na ścieżce (im bliżej pliku, tym wyżej), na końcu `$GIT_DIR/info/attributes`. Makra `[attr]` honorowane tylko tam, gdzie honoruje je git: plik w korzeniu, plik globalny i `info/attributes`. Uwzględniamy `core.ignorecase`.
  - **Plik globalny trzeba *rozwiązać*, nie odczytać dosłownie — poprawione 2026-08-05.** Wartość `core.attributesFile` szła prosto do `Path::new`, więc `~/attrs` szukało katalogu nazwanego dosłownie `~`, a przy **nieustawionym** kluczu domyślna ścieżka XDG nie była czytana w ogóle. Git robi jedno i drugie, zmierzone na 2.55: nieustawione → `$XDG_CONFIG_HOME/git/attributes`, a przy pustym albo nieustawionym `XDG_CONFIG_HOME` → `$HOME/.config/git/attributes`; `~/nazwa` i `~użytkownik/nazwa` rozwijane tak jak przy `core.excludesFile`; **pusta** wartość wyłącza plik i **nie** wraca do XDG.
  - Konsekwencja była tej samej klasy co reszta tej sekcji: linia `text` w pliku globalnym przywraca konwersję na ciphertexcie, a ani odmowa na ścieżce clean, ani bramka `status` tego pliku nie dostawały. **Zmierzone, 2 MB:** ta sama linia w drzewie dawała odmowę i `git add` kodem 128, a w `~/.config/git/attributes` — `git add` kodem **0**, 27 zjedzonych bajtów `CR`, udany commit, checkout bez pliku, i `status` mówiący `VERDICT: no findings.` Osiągalne wyłącznie tam, gdzie sekcja zarządzana milczy (plik globalny stoi **niżej** niż `.gitattributes` z drzewa), czyli po dopisaniu wzorca bez `sync` — a zwykłe `*.sh text eol=lf` w pliku globalnym jest rzeczą normalną.
  - `gix-path` wszedł przy tym jako zależność bezpośrednia i **nie dołożył ani jednego pakietu** — pięć crate'ów w grafie już od niego zależy. Testy: `gitconfig::tests::the_global_attributes_file_resolves_where_git_resolves_it` (pięć kształtów; różnica środowiska wchodzi argumentem, bo `HOME` należy do procesu, a ustawienie go w teście wymagałoby `unsafe`) oraz `tests/attributes.rs::a_text_line_in_the_users_global_attributes_file_is_refused_like_any_other`.
- **Werdykt na osi `filter`:** ścieżka zadeklarowana, dla której git nie rozwiązuje `filter=git-xcrypt`, jest **luką w konfiguracji** i kończy kodem **`2`** (do 2026-08-05 był to kod `5` — patrz „kody wyjścia" → precedencja werdyktu). Wartości `unset`, `unspecified`, `set` i obcy sterownik są tu równoważne — żadna z nich nie uruchamia naszego filtra.
- **Werdykt na osi `text` — dodany 2026-08-05, ten sam kod `2`.** Sekcja zarządzana pisze `-text` na każdej szyfrowanej ścieżce właśnie po to, żeby własna konwersja CRLF gita nie dotknęła ciphertextu. Linia, która ją przebija, przywraca konwersję. **Zmierzone na git 2.55, przy świeżo uruchomionym `sync`, więc żadne inne sprawdzenie w tej komendzie nie miało zastrzeżeń:** `.gitattributes` z `sekrety/** text` pod sekcją zarządzaną, plik 2 MB → z ciphertextu zniknęły 34 bajty `CR`, `git add` i `git commit` skończyły **kodem 0**, a checkout nie przeszedł uwierzytelnienia i **nie zostawił pliku w ogóle**. Tego, co zacommitowano, nie odszyfruje już nikt i żadnym kluczem. `status` wypisywał wtedy `VERDICT: no findings.` i kończył `0`.
  - **Dlaczego luka, a nie nota:** nierozwiązany `filter` kosztuje jawny sekret, a to kosztuje bezpowrotnie utracony plik. Obie odpowiedzi brzmią „twoja deklaracja nie jest egzekwowana", więc mają ten sam kod. Różni je remedium i komunikat: przy tej luce nic **nie** leży jawnie, więc raport nie każe rotować sekretu ani uruchamiać `init` (żadna z komend narzędzia nie rusza linii napisanej przez użytkownika) — nazywa winną linię wraz z plikiem i numerem wiersza.
  - **Zmierzona tabela** (git 2.55, plik 2 MB, werdykt = round-trip bajt w bajt przez `git add`, `commit`, `rm`, `git checkout`):

    | `text` | `eol` | wynik |
    | --- | --- | --- |
    | `unset` (`-text`, `binary`) | dowolne | nietknięty — `-text` bije `eol` |
    | `auto` | dowolne | nietknięty — detekcja binarna widzi wiodący NUL |
    | `unspecified` | brak | nietknięty, przy `core.autocrlf` = `false`, `true` i `input` |
    | `set` | dowolne | **konwersja, plik przepada przy checkoucie** |
    | `unspecified` | `lf` / `crlf` | **konwersja, plik przepada przy checkoucie** |

  - **Ostatni wiersz jest niespodzianką i nie jest przypadkiem naszej implementacji — jest gitowy.** W `convert_attrs` sam atrybut `eol` podnosi nieokreślone `crlf_action` prosto do `CRLF_TEXT_INPUT`/`CRLF_TEXT_CRLF`, a detekcję binarną konsultują wyłącznie warianty `CRLF_AUTO*`. Wiodący NUL naszego magic nie ratuje więc niczego. `-text` jest wyjęte, bo przy `CRLF_BINARY` git pomija atrybut `eol` w całości — i dokładnie to kupuje sekcja zarządzana.
  - **Wiersze bezpieczne są tak samo nośne jak niebezpieczne.** Bramka zapalająca się na `text=auto` albo na zwykłym `core.autocrlf=true` uczy użytkownika ją ignorować, a ignorowana bramka nie chroni niczego. Wszystkie osiem bezpiecznych kształtów ma test round-tripu, nie tylko test werdyktu.
- **Oś `diff` sprawdzona i zostawiona bez werdyktu — 2026-08-05.** Zmierzone na tych samych plikach: obca linia ustawiająca `diff=lfs`, `-diff` albo `diff` na ścieżce zadeklarowanej daje narzut dokładnie `38` bajtów, `rc=0` przy checkoucie i round-trip bajt w bajt. Kosztuje wyłącznie czytelny `git diff` (plaintext znika z różnicy). Żadnego bajtu w repozytorium to nie rusza, więc ani luka, ani nota — trzecia oś świadomie nie powstaje.
- **Brak fałszywych alarmów:** rozstrzyga wartość atrybutu dla ścieżek objętych wzorcem, a nie sama obecność obcej linii. `*.psd filter=lfs` pod sekcją zarządzaną jest zwyczajne i kończy kodem `0`. Lista plików z liniami `filter` zostaje **notą**, wypisywaną z uczciwym werdyktem: albo „któraś z nich sięga zadeklarowanej ścieżki — patrz luka wyżej", albo „sprawdzone wobec każdej zadeklarowanej ścieżki w indeksie, git nadal rozwiązuje `filter=git-xcrypt`".
- **Granica:** rozstrzygamy wyłącznie ścieżki, które indeks już zna. Wzorzec, do którego jeszcze nie pasuje żaden śledzony plik, nie ma czego rozstrzygać — i nota mówi to wprost.
- **Bilans zależności, zmierzony:** `gix-attributes` **nie było** w grafie (`cargo tree -i gix-attributes` → „did not match any packages”), więc raport przeglądu 3 mylił się co do przesłanki. Wniosek pozostaje w mocy: `cargo add gix-attributes` daje `Locking 1 package`, bo wszystkie jego zależności (`bstr`, `gix-glob`, `gix-path`, `gix-quote`, `gix-trace`, `gix-features`, `smallvec`, `thiserror`, `unicode-bom`) są już w grafie. **Jeden crate, zero przechodnich**, `cargo deny check licenses` → `licenses ok`.
- **Koszt, zmierzony** (build `--release`, 10 002 zadeklarowane pliki w 100 katalogach, `status` w całości, mediana z pięciu przebiegów): bez rozstrzygania **18 ms**, z rozstrzyganiem **22 ms**. Ten sam pomiar z dodatkowym `.gitattributes` w każdym ze 100 katalogów: **22 ms → 34 ms**. Koszt rośnie z liczbą plików atrybutów, nie z liczbą ścieżek — stos jest budowany raz na przebieg.

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

Reguła, w pełnej postaci odtworzonej w `src/eol.rs::looks_binary`:

1. **bajt NUL** gdziekolwiek → binarny;
2. **samotny `CR`** (bez następującego `LF`) → binarny. Reguła nieoczywista, ale konieczna: bez niej normalizacja nie jest domknięta na własnym wyjściu i plik po checkoucie wraca zmieniony;
3. **za dużo znaków sterujących**, dokładnie `(drukowalne >> 7) < niedrukowalne`, czyli **jeden niedrukowalny na 128 drukowalnych**. Zmierzone na git 2.55 przy `* text=auto`: 127 : 1 → binarny, 128 : 1 → tekst, 255 : 2 → binarny, 256 : 2 → tekst. Próg ma własny wektor testowy;
4. `BS`, `TAB`, `FF` i `ESC` liczą się jako drukowalne; **`DEL` (0x7f) jako niedrukowalny**, mimo że leży powyżej `0x20`;
5. bajty `≥ 0x80` liczą się jako **drukowalne**, dlatego UTF-8 jest poprawnie rozpoznawane jako tekst;
6. **końcowy bajt `SUB` (0x1A)** — DOS-owy znacznik końca pliku — jest po skanie odejmowany od licznika niedrukowalnych. Jeden bajt i tylko ostatni. To odpowiednik zamknięcia `gather_stats` w gicie: `if (size >= 1 && buf[size-1] == '\032') stats->nonprintable--;`.

**Reguła jest zamrożona wraz z formatem od 2026-08-04, a nie wcześniej.** Do tego dnia punkt 6 nie istniał i był jedynym odstępstwem od gita z 18 kształtów sprawdzonych wobec prawdziwego gita; wcześniejsze wersje tego dokumentu opisywały go jako znany, świadomie odłożony dług (element `S-08`). Domknięte przed pierwszym wydaniem, bo dopóki nie istnieje ani jedno repozytorium poza tym projektem, poprawka kosztuje jedną linię; po wydaniu przesuwałaby granicę tekst/binarny, czyli przepisywała ciphertext istniejących plików, i wymagałaby nowego `suite`.

Zmierzone na git 2.55 przed zmianą, nie odczytane ze źródeł: `* text=auto`, treść `a\r\n\x1a` → blob `61 0a 1a`, czyli git znormalizował CRLF i uznał plik za tekst; nasz `looks_binary` liczył wtedy `printable = 1`, `nonprintable = 1` i mówił „binarny". Zmierzone też granice korekty, każda przez to, czy CR przeżył w blobie: `a\r\n\x1a\x1a` → binarny (odejmowany jest jeden `SUB`, nie oba), `a\x1ab\r\n` → binarny (tylko ostatni bajt), `a\x01\r\n\x1a` → binarny (korekta jest warta jeden bajt i zużywa ją `0x01`), 128 drukowalnych + `0x01` + `SUB` → tekst, przy 127 → binarny. Przypadek bez CR sprawdzony w drugą stronę, przez checkout przy `core.autocrlf=true`: `\n\x1a` wraca jako `\r\n\x1a` (tekst), `\x01\n\x1a` wraca bez zmian (binarny) — stąd `saturating_sub`, bo licznik dochodzi tu do zera.

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

# nazwa ze spacją — domknięta cudzysłowem, jak w .gitattributes
"moje sekrety/"
"moje sekrety/*.sh"  text eol=lf

# wyjątek — jawny mimo dopasowania wyżej
!sekrety/README.md
!"moje sekrety/README.md"
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

**Semantyka dopasowania — wielkość liter, rozstrzygnięte 2026-08-05 (otwarta decyzja 13).** Wzorce dopasowują się **ze zwinięciem wielkości liter ASCII, bezwarunkowo i na obu osiach**: `sekrety/` obejmuje `Sekrety/db.env` i `SEKRETY/db.env`, `*.env` obejmuje `top.ENV`, a negacja `!sekrety/README.md` wyłącza również `Sekrety/README.MD`. Trzy rzeczy warto tu wiedzieć:

- **Nie czytamy `core.ignorecase`.** Zwijanie jest bezwarunkowe, więc to samo repozytorium szyfruje ten sam zbiór plików na każdej maszynie. To ustawienie git dobiera sam, sondując system plików, i nie jest wersjonowane — czytanie go na ścieżce clean łamałoby determinizm dokładnie tak, jak łamałoby go czytanie `core.autocrlf`.
- **Wygenerowane linie w `.gitattributes` zwijają razem z filtrem** — każda litera ASCII jest w nich zapisana jako klasa `[xX]`, więc `sekrety/` renderuje się jako `**/[sS][eE][kK][rR][eE][tT][yY]/** -text diff=git-xcrypt`. Bez tego linia byłaby węższa niż filtr, a to jest ten wariant, który kosztuje plik.
- **Zwijanie kończy się na ASCII**, dokładnie tam, gdzie kończy je git: `łąka/` nie obejmuje `ŁĄKA/`. Powód jest zmierzony, nie ostrożnościowy — `.gitattributes` operuje na bajtach, więc `[łŁ]` jest zbiorem czterech bajtów i nie dopasowuje żadnej pisowni. Szczegóły i pomiary: „Otwarte decyzje" poz. 13.

- **`binary`** jest synonimem `-text`, dodatkowo wyłącza `diff=git-xcrypt` w wygenerowanej linii kosmetycznej — tak jak makro `binary` w gicie oznacza `-text -diff`.
- **`eol=` przy `-text` jest bezskuteczne** — odtwarzamy zmierzone „`-text` bije `eol`". Kombinacja jest bezsensowna, ale nie niebezpieczna: ostrzeżenie na `stderr`, bez przerywania operacji.
- **Atrybuty na linii z negacją to błąd** — plik nie jest szyfrowany, więc nie ma czego konwertować. Fail closed.
- **`text=auto` jest jedynym atrybutem zależnym od treści.** Używa reguły zmierzonej wyżej — NUL albo nadmiar znaków sterujących poniżej `0x20` — ale **wyłącznie jako funkcji treści**, nigdy z zaglądaniem do indeksu, w odróżnieniu od gita. Skoro jest zachowaniem domyślnym, decyduje o ciphertexcie większości plików: reguła jest **zamrożona wraz z formatem** i ma **własne wektory testowe**, obok wektorów formatu i wektorów z RFC 5297. Konsekwencja tej semantyki, identyczna jak w gicie: plik, który przestaje być tekstem, przestaje być normalizowany, więc w różnicy odszyfrowanej treści widać wtedy zmianę wszystkich linii doklejoną do właściwej edycji. Determinizmu to nie narusza i treści nie uszkadza.
- **`eol=` celowo nie trafia do nagłówka.** Gdyby trafiło, zmiana deklaracji z `eol=lf` na `eol=crlf` nie zadziałałaby na istniejące pliki aż do ich ponownego dodania. Trzymamy w nagłówku wyłącznie fakt „normalizowano", bo tylko on jest niebezpieczny przy rozjeździe. Wybór końca linii przy smudge jest samonaprawialny: gdy padnie źle, następny clean i tak normalizuje z powrotem do LF, ciphertext wychodzi ten sam, a `git status` zostaje czysty. Pliki binarne mają bit `0` i są zapisywane verbatim, więc nie dotyczy ich to w ogóle.
- **Nieznany atrybut to błąd**, nie ostrzeżenie — fail closed, ta sama zasada co przy nieznanym `suite` i nieznanym bicie `flags`.
- **Poza zakresem:** `working-tree-encoding` (konwersja kodowania znaków, np. UTF-16). Git to potrafi, my nie — zapisane w `README.md` §Known limitations.

### Spacja w nazwie: cudzysłów, nie backslash — rozstrzygnięte 2026-08-05

Wzorzec kończy się na pierwszym białym znaku, bo po nim stoją atrybuty. Nazwa zawierająca spację potrzebuje więc sposobu, żeby powiedzieć „ta spacja należy do nazwy". Do 2026-08-05 był nim backslash (`moje\ sekrety/`); od tej daty jest nim **cudzysłów, dokładnie taki, jaki zna `.gitattributes`**:

```
<wzorzec> [białe znaki <atrybuty>]

wzorzec niecytowany:  ciąg bez białych znaków, nie zaczynający się od "
wzorzec cytowany:     "…" z cytowaniem w stylu C, tym samym, które rozpakowuje git
                      \" → "   \\ → \   \a \b \f \n \r \t \v oraz ósemkowe \nnn
negacja:              ! stoi PRZED cudzysłowem:  !"moje sekrety/README.md"
```

Powody, oba wiążące:

- **Backslash niósł dwa znaczenia naraz.** Na poziomie linii był ucieczką białego znaku, a wewnątrz wzorca jest ucieczką metaznaku globa (`\*` to dosłowna gwiazdka) — o tym, które z nich obowiązuje, decydował następny znak. Po zmianie backslash znaczy wyłącznie to drugie, a wzorzec po rozpakowaniu cudzysłowu idzie do `gix_glob::Pattern` w postaci dosłownej.
- **Backslash nie domykał drugiego trudnego kształtu — spacji na końcu nazwy.** `moje sekrety\ ` musiałoby stać na końcu linii, a każdy edytor obcinający końcowe białe znaki kasuje tę spację bez słowa i zostaje wzorzec o innym znaczeniu. Cudzysłów zamyka oba kształty jednym mechanizmem: `"moje sekrety/"` i `"sekrety /"`.

**Migracja jest fail-closed i nazwana po imieniu.** Stary zapis rozkłada się dziś na wzorzec `moje\` i nieznany atrybut `sekrety/`, więc plik i tak zostaje odrzucony — ale komunikat „nieznany atrybut" niczego nie tłumaczy w pliku napisanym raz i od tamtej pory nieotwieranym. Rozpoznawane są więc dwa kształty, oba z gotową linią zastępczą w treści błędu:

- **wzorzec kończący się backslashem** — pozostałość po `\ `; komunikat odtwarza linię starą regułą i pokazuje jej cytowany odpowiednik;
- **wzorzec cytowany, którego końcowe słowa są atrybutami** (`"sekrety/*.sh text eol=lf"`) — czyli stara linia zacytowana w całości. To jedyny kształt, który bez tej siatki zmieniłby znaczenie **po cichu**: wzorzec nie pasowałby do niczego, a plik przestałby być szyfrowany bez ostrzeżenia. Liczy się wyłącznie **końcowy** ciąg słów-atrybutów, więc katalog `moje pliki tekstowe/` przechodzi bez zaczepienia; nazwa kończąca się dosłownie słowem `text` zapisuje się `"… tex[t]"` (ten sam zbiór ścieżek, wildmatch po obu stronach).

**Rendering do `.gitattributes` cytuje z powrotem.** Wzorzec z białym znakiem, z wiodącym `"` albo z wiodącym `#` jest w wygenerowanej linii cytowany (`"**/moje sekrety/**" -text diff=git-xcrypt`); backslash przechodzi bez zmian, bo wildmatch jest po obu stronach ten sam, a cytowanie podwaja go tylko na potrzeby własnej warstwy. Wiodący `#` bez cudzysłowu byłby dla gita komentarzem, czyli linią, której po prostu nie ma — a to jest brak `-text` na ścieżce szyfrowanej.

**Świadomie przyjęte ograniczenie:** ósemkowe ucieczki, które nie składają się na poprawny UTF-8, są odrzucane — plik `.git-xcrypt` jest czytany jako tekst. Nazwa pliku spoza UTF-8 pozostaje więc niedeklarowalna, tak samo jak przed zmianą.

**Konfigurację czytamy biblioteką, nie procesem potomnym.** `gix-config` (gitoxide) daje precedencję system/global/repo/worktree wraz z `include`, kompiluje się do środka binarki i nie łamie wymogu samowystarczalności z „Założeń technicznych". Wywoływanie `git config` odpada z powodu samowystarczalności — argument o N spawnach był prawdziwy dla prototypu z procesem na plik i przy filtrze długożyjącym już nie obowiązuje, ale wniosek zostaje. Pozostaje jedna binarka `git-xcrypt` w dwóch trybach rejestrowanych przez `init` (`process` i `diff`; reszta komend wywoływana przez użytkownika); żadnego osobnego programu pomocniczego ani demona.

**Dwa zmierzone ograniczenia `gix-config`, świadomie przyjęte** (oba dotyczą wyłącznie EOL, więc są samonaprawialne — następny clean i tak normalizuje do LF):

- `GIT_CONFIG_PARAMETERS`, czyli `git -c core.autocrlf=…`, jest dla filtra **niewidoczne** (`gix-config` czyta `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n`);
- `includeIf` w konfiguracji **globalnej** nie jest rozwijane.

Determinizmu żadne z nich nie łamie, bo ścieżka `clean` konfiguracji nie czyta w ogóle.

**Trzecie z tej listy zostało naprawione 2026-08-05 i nie było ograniczeniem EOL.** Zapis „w podłączonym worktree czytany jest `config.worktree` **głównego** checkoutu" był prawdziwy, ale wniosek „dotyczy wyłącznie EOL, więc jest samonaprawialny" — nie. `config.worktree` niesie też `core.attributesFile`, czyli źródło w stosie atrybutów gita, a tam pomyłka kosztuje plik, nie jeden checkout z niewłaściwym końcem linii. **Zmierzone na git 2.55, 2 MB:** podłączony worktree, którego `config.worktree` wskazywał plik z linią `vault/** text` — `git check-attr text` odpowiadał tam `set`, a w głównym checkoucie `unspecified`; `git add` skończyło **kodem 0**, bo odmowa z „Odmowa, gdy git przekonwertowałby ciphertext" nigdy nie zobaczyła tego pliku, z bloba zniknęło 40 bajtów, a checkout **nie zostawił pliku w ogóle**.

`gitconfig::open_full` składa więc kaskadę sam, zamiast wołać `File::from_git_dir`, i dzieli katalogi tak, jak dzieli je git: `config` ze wspólnego, `config.worktree` z katalogu **tego** checkoutu. Przy okazji zamknięty drugi kształt z tej samej funkcji: `extensions.worktreeConfig = true` bez zapisanego jeszcze `config.worktree` wywracało **każdą** operację gita w repozytorium (`git add` kodem 128), bo `gix-config` czyta rozszerzenie jako obietnicę istnienia pliku, a git jako pozwolenie, żeby zajrzeć — plik powstaje dopiero przy pierwszym `git config --worktree`. Zmierzone: git w tym stanie wykonywał `add`, `commit` i `status` kodem 0. Fail-closed, więc nic nie trafiło jawnie do bazy obiektów, ale to jest awaria uruchamiana poleceniem z dokumentacji samego gita. Tolerancja kończy się na „brak": plik obecny i nieparsowalny nadal przerywa operację, w obu pozycjach kaskady.

Sprawdzone przy okazji i **zgodne, więc nietknięte**: `info/attributes` git czyta ze wspólnego katalogu również w podłączonym worktree, a nie z `worktrees/<nazwa>/info/` — czyli rozwiązanie, które już było w kodzie, jest poprawne. Testy: `tests/attributes.rs::a_linked_worktrees_own_config_is_the_one_that_counts`, `tests/filter_edge_cases.rs::a_per_worktree_config_git_has_not_written_yet_does_not_stop_the_filter`.

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
9. ~~**Kod wyjścia `5` jest przeciążony.**~~ Rozstrzygnięte 2026-08-04: **nowy kod `6` — „nie dało się ustalić"**, a `5` znaczy odtąd wyłącznie ekspozycję. Tabela kodów została świadomie rozszerzona mimo zamrożenia, bo koszt jest zerowy przed pierwszym wydaniem, a alternatywa (degradacja płytkiego klonu do noty) chowałaby „nie wiem" pod kodem `0`. **Domknięte 2026-08-05:** `5` niósł jeszcze trzecią odpowiedź — lukę konfiguracji — więc repozytorium, które nigdy nie uruchomiło `init`, dostawało „znaleziono ekspozycję, rotuj sekret". Luka konfiguracji ma odtąd kod `2` z zamrożonej tabeli (nowego kodu nie dokładano), a precedencja brzmi **`2` > `5` > `6` > `0`**, przy uzasadnieniu właściciela „bez poprawnej konfiguracji dane są nic nie warte". Szczegóły: „Integracja z git" → kody wyjścia → precedencja werdyktu.
10. ~~**Czy `status` ma rozwiązywać atrybuty gita, zamiast je nazywać.**~~ Rozstrzygnięte 2026-08-04: **tak, przez `gix-attributes`** — patrz „Integracja z git" → „Rozstrzyganie atrybutów przez `status`".
11. **Kolizja kodu `1` przy `lock` i `sync --check`.** Przerwanie przez użytkownika, błąd argumentów i porażka zapisu w połowie dają przy `lock` ten sam kod; `sync --check` używa `1` dla „sekcja nieaktualna". Rozróżnienie wymaga ruszenia zamrożonej tabeli.
12. **Skracanie nazwy pliku tymczasowego przy nazwach ≥ 224 B** oznacza, że residuum po zabitym przebiegu na takim pliku może nie zostać zamiecione przez `lock`. Jeśli obietnica „po `lock` nie zostaje żaden plaintext" ma być bezwarunkowa, potrzebny jest inny schemat nazw — np. rejestr residuum w `.git/`.
13. ~~**Semantyka wzorców wobec `core.ignorecase` i normalizacji Unicode w nazwach plików.**~~ **Rozstrzygnięte 2026-08-05: dopasowanie wzorców w `.git-xcrypt` zwija wielkość liter ASCII, bezwarunkowo.** Uzasadnienie właściciela: to jest najbezpieczniejsze rozwiązanie.
    - **Problem, który to zamyka — zmierzone.** `.git-xcrypt` deklaruje `sekrety/`, użytkownik tworzy `Sekrety/db.env`. Na macOS (APFS) i na Windows (NTFS) to **jeden katalog** — `cd sekrety` wchodzi do `Sekrety`, `ls` pokazuje jedną pozycję, więc w katalogu roboczym **nie da się zobaczyć pomyłki**. Przy dopasowaniu bajtowym plik nie był szyfrowany, `git add` kończył kodem `0`, a `AWS_SECRET=hunter2` lądowało w bazie obiektów jawnie.
    - **Bezwarunkowość jest tu istotą, nie szczegółem.** Wariant „zwijaj wtedy, gdy zwija git" wymagałby czytania `core.ignorecase` na ścieżce clean, a to ustawienie **nie jest wersjonowane** (git ustawia je sam, sondując system plików przy `init`/`clone`) — to samo repozytorium szyfrowałoby wtedy inny zbiór plików na macOS niż na Linuksie. Dokładnie ten argument wyklucza `core.autocrlf` ze ścieżki clean („Końce linii"). Zwijanie bezwarunkowe nie czyta niczego, więc determinizm zostaje nienaruszony: decyduje sama deklaracja, na każdej maszynie tak samo.
    - **Rendering musi zwijać razem z selekcją, i robi to sam z siebie.** Zmierzone: wyrenderowana linia `**/sekrety/**` przy `core.ignorecase = false` (czyli na ext4) odpowiada dla `Sekrety/db.env` **`unspecified`**. Gdyby selekcja zwijała, a rendering nie, filtr szyfrowałby ścieżkę, której `-text` nie chroni — czyli „węższy" wariant złamania reguły z „Konstrukcji catch-all", ten kosztujący plik przy checkoucie. Rozwiązanie zmierzone i działające: `**/[sS][eE]krety/** -text` dopasowuje `sekrety/a.env`, `Sekrety/a.env` **i** `SEkrety/a.env`, dając `unset` — **niezależnie od `core.ignorecase`**. Renderer emituje więc każdą literę ASCII jako klasę `[xX]` (`src/gitattributes.rs::fold_case`).
    - **Zakres: ASCII — wybrany świadomie, i tak samo daleko sięga git.** `gix-glob` przy `Case::Fold` używa `to_ascii_lowercase` (`gix-glob-0.27.0/src/wildmatch.rs:61`). Git też: przy `core.ignorecase = true` wzorzec `łąka/**` nie dopasowuje ani `ŁĄKA/a.env`, ani `Łąka/a.env` (`unspecified`), podczas gdy `sekrety/` dopasowuje `Sekrety/db.env`. Nasza granica pokrywa się więc z gitową. **Dalej się nie da**, i to jest pomiar, nie ostrożność: `.gitattributes` operuje na bajtach, więc `[łŁ][ąĄ]ka/**` jest zbiorem **czterech bajtów**, nie dwóch znaków, i nie dopasowuje **żadnej** pisowni. Rendering nie ma jak wyrazić zwinięcia spoza ASCII, więc selekcja, która by je zwijała, byłaby szersza od linii, która ją chroni. Ograniczenie zapisane w `README.md` §Known limitations.
    - **Lista nigdy-nie-szyfrowanych zwija tak samo** (`config::is_never_encrypted`). Na systemie nieczułym na wielkość liter `.GITATTRIBUTES` **jest** plikiem atrybutów, więc zaszyfrowanie go zastąpiłoby linię catch-all ciphertextem i wyłączyło filtr dla **całego** repozytorium, nie dla jednego pliku. Koszt w drugą stronę jest zapisany: na ext4 plik nazwany celowo `sekrety/.GITATTRIBUTES` zostaje jawny. Kierunek wybrany dlatego, że wygenerowane linie wykluczeń też zwijają — a filtr szyfrujący ścieżkę, na której te linie przywracają domyślne ustawienia gita, zostawiłby ciphertext bez `-text`.
    - **Co z tego zniknęło.** Sekcja `undetermined` w `status` o `core.ignorecase` została **usunięta**. Powstała dlatego, że semantyka była nierozstrzygnięta („Whether a pattern should fold is not settled, so nothing here guesses"); po rozstrzygnięciu jej warunek — „dopasowanie ze zwijaniem wybiera ścieżkę, której dopasowanie bajtowe nie wybiera" — nie może już być prawdziwy, bo selekcja **jest** dopasowaniem ze zwijaniem. Komunikat, który nie ma jak się zapalić, jest gorszy niż jego brak. `Config::selected_only_when_folding_case` usunięte razem z nim. `core.ignorecase` zostaje czytane **wyłącznie** przez `AttributeResolver`, bo tam odtwarzamy zachowanie gita, a nie podejmujemy własną decyzję.
    - **Normalizacja Unicode — zmierzone i zgodne z gitem, więc bez zmian.** APFS zapisuje nazwę w NFD, a git przy `core.precomposeunicode = true` (domyślnie na macOS) podaje ją w NFC — filtr dostaje NFC i dopasowuje poprawnie. Wzorzec zapisany w NFD (tyle wstawia dopełnianie w powłoce) nie pasuje do niczego — **i git zachowuje się identycznie**: `.gitignore` z wzorcem NFD nie ukrywa katalogu, ten sam wzorzec w NFC ukrywa. Rozbieżności z gitem nie ma, więc nie ma czego naprawiać; zostaje w tym punkcie jako fakt, nie jako dług.
    - Testy: `tests/attributes.rs::a_pattern_reaches_every_ascii_spelling_of_a_name_and_the_rendered_line_keeps_up` (obie osie naraz, przy `core.ignorecase` ustawionym na `false` **i** `true`), `gitattributes::tests::folding_leaves_every_other_construct_meaning_what_it_meant`, `gitattributes::tests::a_macro_opening_is_still_recognised_before_anything_is_folded` oraz wiersze w `config::tests`.
14. ~~**Podpisywanie artefaktów wydania.**~~ **Rozstrzygnięte 2026-08-05: atestacje proweniencji GitHuba** (`actions/attest-build-provenance`), nie własny klucz. Każde opublikowane archiwum dostaje atestację; weryfikacja to `gh attestation verify <archiwum> --repo <owner>/<repo>`.
    - **Dlaczego nie własny klucz.** Żeby wydanie zostało automatyczne, klucz prywatny musiałby zamieszkać w sekretach tego repozytorium — to **przesuwa** wektor zaufania, a nie zamyka go. Do tego utrata takiego klucza jest tą samą klasą awarii, którą ten dokument opisuje przy kluczu repozytorium, a projekt jest jednoosobowy. Atestacja nie ma klucza do zgubienia: podpis wiąże się z tożsamością workflow przez OIDC.
    - **Atestacja mówi więcej niż podpis.** Nazywa commit i przebieg, z którego powstał plik — czyli odpowiada wprost na tę część kontrargumentu z PRD FR-011, która mówiła o „łańcuchu od źródła".
    - **Kotwicą zaufania jest GitHub i Sigstore, nie autor.** Kto nie ufa GitHubowi, nie zyskuje z tego nic — to jest przyjęty koszt tego wyboru, nie przeoczenie.
    - **Druga połowa kontrargumentu zostaje otwarta świadomie: build nie jest odtwarzalny.** `trim-paths` nie jest ustawione, a toolchain nie jest przypięty, więc ścieżki bezwzględne i wersja kompilatora trafiają do binarki i nikt z zewnątrz nie odtworzy tych bajtów, żeby porównać sumy. Obecność atestacji **nie może** być czytana jako domknięcie tej połowy. Gdyby kiedyś wejść w odtwarzalność, to jest osobny element o rozmiarze roadmapowym: przypięty toolchain, `trim-paths`, `SOURCE_DATE_EPOCH` i dwa niezależne buildy do porównania.
15. ~~**Czy plik klucza dostaje na Windows własne ACL.**~~ **Rozstrzygnięte 2026-08-05: nie dostaje, i zostaje to zapisaną granicą.** Zawężenie ACL do właściciela wymaga `windows-sys` i bloku `unsafe`, czyli złamania reguły „zero `unsafe`" wymuszanej przez `unsafe_code = "forbid"` — a ta reguła czerpie wartość właśnie stąd, że jest bezwyjątkowa. Wybór brzmiał więc nie „dziesięć linii czy nie", tylko „czy dla tej jednej rzeczy przestaje obowiązywać jedna z twardych reguł projektu"; właściciel wybrał regułę.
    - **Co to naprawdę kosztuje.** Model zagrożeń z §Bezpieczeństwo i tak stawia atakującego z dostępem do konta użytkownika **poza** zakresem, a `0600` na uniksie chroni przed innymi kontami na tej samej maszynie — nie przed kimś, kto już jest tym użytkownikiem. Na Windows ochroną jest katalog, w którym plik powstaje.
    - **Gdzie to jest powiedziane użytkownikowi.** `README.md` mówi to dwa razy i celowo: przy samym `export-key` („na Windows to katalog, który wybierzesz, *jest* ochroną") oraz w §Known limitations, z powodem i z radą, żeby wybrać katalog czytelny tylko dla własnego konta. Podwójnie, bo pierwsze miejsce sąsiaduje ze zdaniem o `0600` i bez tego zastrzeżenia czytałoby się jak obietnica obowiązująca wszędzie.
    - **Trzecia droga zbadana i nieodrzucona na przyszłość:** crate enkapsulujący `unsafe` u siebie zostawiłby naszą regułę nietkniętą, bo `unsafe_code = "forbid"` dotyczy wyłącznie tej skrzyni. Nie badano, czy taki crate istnieje, jest utrzymywany i przechodzi `cargo deny` — gdyby ochrona ACL kiedykolwiek stała się potrzebna, to jest miejsce, od którego zacząć, a nie blok `unsafe` u nas.
