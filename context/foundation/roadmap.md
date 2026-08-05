---
project: "git-xcrypt"
version: 1
status: active
created: 2026-08-03
updated: 2026-08-04
prd_version: 1
main_goal: learn
top_blocker: decisions
---

# Roadmap: git-xcrypt

> Wywiedzione z `context/foundation/prd.md` (v1) + sonda bazy kodu z 2026-08-03.
> Edytuj na miejscu; archiwizuj po zastąpieniu.
> Elementy są wymienione w kolejności zależności. Tabela `At a glance` to indeks.
> Nagłówki sekcji i etykiety pól są po angielsku, bo `/10x-archive` dopasowuje je dosłownie przy zamykaniu elementów. Treść jest po polsku.

## Vision recap

Pojedynczy deweloper trzyma sekrety swoich projektów poza repozytorium i kopiuje je ręcznie między maszynami. Ból uderza przy klonie na nowej maszynie, przy zmianie sekretu wymagającej synchronizacji i przy zakładaniu każdego nowego projektu.

Produkt rozstrzyga na podstawie wzorców ścieżek, które pliki opuszczają maszynę wyłącznie w postaci zaszyfrowanej, i gwarantuje, że ta sama treść zawsze daje ten sam ciphertext. Wyróżnikiem wobec projektów bazowych jest samowystarczalna binarka bez zależności od systemowego `gpg`.

## North star

**S-01: Przezroczyste szyfrowanie w jednym repozytorium** — po tym elemencie wiadomo, czy reguła domenowa z PRD w ogóle działa: czy filtr gita potrafi szyfrować w locie, czy szyfrowanie jest powtarzalne i czy `git status` po checkoucie zostaje czysty.

> Gwiazda przewodnia to najmniejszy element od początku do końca, którego pomyślne dostarczenie dowodzi podstawowej hipotezy produktu — umieszczony tak wcześnie, jak pozwalają wymagania wstępne, bo wszystko inne ma znaczenie dopiero wtedy, gdy to działa.

## At a glance

| ID    | Change ID                    | Outcome (użytkownik może …)                                             | Prerequisites | PRD refs               | Status   |
| ----- | ---------------------------- | ----------------------------------------------------------------------- | ------------- | ---------------------- | -------- |
| F-01  | git-integration-test-harness | (foundation) weryfikować zachowanie na prawdziwym repozytorium git      | —             | §Guardrails            | done     |
| S-01  | transparent-encrypt-decrypt  | commitować plik i dostać ciphertext w repo, plaintext w katalogu roboczym | F-01          | FR-001, FR-004, FR-005 | done     |
| S-02  | gitignore-style-config       | wskazać pliki do szyfrowania w składni `.gitignore`                      | S-01          | FR-002, FR-003         | done     |
| S-03  | key-export-and-unlock        | odzyskać sekrety po klonie na drugiej maszynie                           | S-01          | US-01, FR-007, FR-008  | done     |
| S-04  | lock-repository              | zamknąć odblokowane repozytorium z powrotem                              | S-03          | FR-009                 | done     |
| S-05  | decrypted-diff               | oglądać różnice na treści jawnej                                         | S-01          | FR-006                 | done     |
| S-06  | encryption-status-check      | sprawdzić, co jest szyfrowane, a co powinno być                          | S-02          | FR-010                 | done     |
| S-07  | cross-platform-binaries      | pobrać gotową binarkę dla swojej platformy                               | S-01, S-08    | FR-011                 | proposed |
| S-08  | binary-detection-parity      | dostać ten sam werdykt tekst/binarny co git, także na pliku z `SUB`     | S-01          | §NFR (trzy platformy)  | done     |

## Streams

Pomoc nawigacyjna — grupuje elementy dzielące łańcuch wymagań wstępnych. Kanoniczna kolejność jest w grafie zależności niżej.

| Stream | Temat                    | Łańcuch                              | Uwaga                                                                        |
| ------ | ------------------------ | ------------------------------------ | ---------------------------------------------------------------------------- |
| A      | Rdzeń szyfrowania        | `F-01` → `S-01` → `S-03` → `S-04`    | Ścieżka gwiazdy przewodniej; niosła całe ryzyko techniczne celu `learn`. **Zamknięta 2026-08-04** — cały łańcuch zrobiony i przejrzany. |
| B      | Konfiguracja i widoczność | `S-02` → `S-06`                      | Dołącza do Strumienia A w `S-01`. **Zamknięta 2026-08-04** — obie decyzje (rozjazd konfiguracji, głębokość skanu) zapadły i są zaimplementowane. |
| C      | Narzędzia pracy          | `S-05`                               | Dołącza do A w `S-01`. **Zamknięta 2026-08-04**; jedyny element bez własnej niewiadomej — ale plan i tak trafił w błędne założenie o `textconv`, sprostowane pomiarem. |
| D      | Dystrybucja              | `S-08` → `S-07`                      | Dołącza do A w `S-01`. **Jedyny otwarty strumień**, i został w nim wyłącznie `S-07`. `S-08` zamknięty 2026-08-04, czyli w wymaganej kolejności: `looks_binary` zamraża się z pierwszym publicznym wydaniem. Nazwa i licencja rozstrzygnięte 2026-08-04. |

## Baseline

> **ZDJĘCIE HISTORYCZNE z 2026-08-03, sprzed `S-01` — nie opisuje stanu bieżącego.** Wszystko, co poniższa lista zgłasza jako nieobecne (CLI, kryptografia, filtry, format pliku, zarządzanie kluczem, testy), powstało w `S-01`–`S-06` i jest w repozytorium; sekcja zostaje wyłącznie jako punkt odniesienia, od którego liczy się zakres tych elementów.

Co jest na miejscu w bazie kodu na dzień 2026-08-03 (sonda + potwierdzenie użytkownika).
Fundament poniżej zakłada ten stan i nie tworzy ponownie niczego, co jest zgłoszone jako obecne.

- **CLI / parsowanie argumentów:** nieobecne — `src/main.rs:1-3` to hello world, brak biblioteki do argumentów.
- **Kryptografia:** nieobecna — `Cargo.toml:7` deklaruje pustą sekcję zależności.
- **Integracja z gitem (filtry):** nieobecna — brak jakiegokolwiek kodu filtrów i wpisów w konfiguracji repozytorium.
- **Format pliku / dane:** nieobecny — brak nagłówka, wersji formatu i wektorów testowych.
- **Zarządzanie kluczem:** nieobecne.
- **Testy:** nieobecne — brak katalogu `tests/`.
- **Wdrożenie / CI:** nieobecne — brak `.github/`; `tech-stack.md` deklaruje GitHub Actions i wydanie sterowane ręcznie, ale nic nie jest zaimplementowane.
- **Obserwowalność:** poza modelem produktu — zasada „nic poza danymi na stdout" w filtrach wyklucza klasyczne logowanie na ścieżce gorącej.
- **Frontend / Backend / Uwierzytelnianie:** nie dotyczy — produkt nie ma interfejsu graficznego, serwera ani logowania.

## Foundations

### F-01: Harness testów integracyjnych na prawdziwym repozytorium git

- **Outcome:** (foundation) istnieje sposób automatycznego uruchomienia narzędzia na prawdziwym repozytorium git w katalogu tymczasowym i sprawdzenia, co faktycznie wylądowało w obiektach gita.
- **Change ID:** git-integration-test-harness
- **PRD refs:** §Success Criteria → Guardrails (brak uszkodzeń plików, determinizm), §Non-Functional Requirements (identyczne zachowanie na trzech platformach)
- **Unlocks:** `S-01` (jego wynik jest obserwowalny wyłącznie przez zachowanie gita), a przez to również `S-03`, `S-04` i `S-06`; zmniejsza ryzyko cichej regresji determinizmu, którego ręczne sprawdzanie nie wychwytuje.
- **Prerequisites:** —
- **Parallel with:** —
- **Blockers:** —
- **Unknowns:** —
- **Risk:** bez tego każdy kolejny element weryfikuje się ręcznie, a akurat determinizm i brak uszkodzeń treści to właśnie te własności, które ręczne sprawdzenie przeoczy. Zakres celowo minimalny — pomocnik tworzący repozytorium, rejestrujący filtr i pozwalający czytać surowe obiekty, nie pełny zestaw testów.
- **Status:** done

## Slices

### S-01: Przezroczyste szyfrowanie w jednym repozytorium

- **Outcome:** użytkownik inicjuje repozytorium jedną komendą, oznacza plik jako tajny i po commicie widzi w obiektach gita wyłącznie ciphertext, w katalogu roboczym plaintext, a `git status` po checkoucie jest czysty.
- **Change ID:** transparent-encrypt-decrypt
- **Zakres poszerzony 2026-08-04:** konstrukcja catch-all wymaga, żeby filtr był **długożyjący** (`filter.git-xcrypt.process`, protokół pkt-line) — proces na plik daje zmierzone 22× spowolnienie. Dochodzi też obowiązkowy test właściwości `passthrough(x) == x`, bo filtr działa odtąd na każdym pliku repozytorium.
- **PRD refs:** FR-001, FR-004, FR-005, §Business Logic, §Non-Functional Requirements (metadane)
- **Prerequisites:** F-01
- **Parallel with:** —
- **Blockers:** —
- **Unknowns:**
  - ~~Który szyfr i jaki układ nagłówka formatu?~~ Rozstrzygnięte 2026-08-04: AES-256-SIV (RFC 5297, `aes-siv`), nagłówek 22 B jako AAD — magic, `format_version`, `suite`, `flags`, `key_id` — plus 16 B SIV; klucz główny 32 B z wyprowadzaniem per suite przez HKDF-SHA-256. Patrz `zalozenia.md` §Kryptografia i format pliku. — Właściciel: użytkownik. Blokuje: nie.
  - ~~Jak `init` wykrywa, że repozytorium jest już skonfigurowane, żeby nie nadpisać klucza?~~ Rozstrzygnięte 2026-08-04: trzy reguły — klucz istnieje → nigdy nie nadpisuj, tylko napraw resztę; klucza brak przy śladach wcześniejszej konfiguracji → odmowa z kodem `2`; klucza brak bez śladów → świeża inicjacja. Bez `--force`. Patrz `zalozenia.md` §Integracja z git. — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** tu zapada format pliku — po tym elemencie każda zmiana formatu psuje istniejące repozytoria, dlatego wersja formatu musi trafić do nagłówka już w pierwszym commicie. Ryzyko zredukowane przed planowaniem: format przepuszczono 2026-08-04 przez listę 16 przyszłych funkcjonalności (odbiorcy, klucze per stanowisko, rotacja, wiele kluczy, tryb blokowy, kompresja, dopełnianie, zmiana szyfru); 13 pozycji obsługuje bez zmian, pozostałe trzy wymusiły bajt `flags` i regułę „od offsetu 22 decyduje `suite`". Kryptografia świadomie nie jest osobnym fundamentem: ląduje w pierwszym elemencie, który jej faktycznie potrzebuje. Potwierdzone w praktyce: oba przebiegi przeglądu znalazły łącznie pięć dróg, którymi plaintext trafiał do bazy obiektów przy `git add` kończącym się kodem `0` — obcinanie białych znaków w ścieżce z pkt-line, stratne dekodowanie ścieżki przez `from_utf8_lossy`, brak `.git-xcrypt` czytany jako „nie szyfruj niczego" — a drugi przebieg znalazł błąd wprowadzony przez naprawę z pierwszego.
- **Status:** done

### S-02: Konfiguracja w składni .gitignore

- **Outcome:** użytkownik wskazuje pliki i katalogi do szyfrowania we własnym pliku konfiguracyjnym o składni `.gitignore` i synchronizuje z niego konfigurację czytaną przez gita.
- **Change ID:** gitignore-style-config
- **PRD refs:** FR-002, FR-003, §Success Criteria → Secondary
- **Prerequisites:** S-01
- **Parallel with:** S-03, S-05, S-07
- **Blockers:** —
- **Unknowns:**
  - ~~Jak nie dopuścić do rozjazdu pliku konfiguracyjnego i konfiguracji czytanej przez gita?~~ Rozstrzygnięte 2026-08-04: konstrukcja catch-all — `.gitattributes` dostaje jedną statyczną linię `* filter=git-xcrypt`, a `.git-xcrypt` jest jedynym źródłem prawdy czytanym przez filtr. Rozjazd przestaje istnieć zamiast być pilnowany. — Właściciel: użytkownik. Blokuje: nie.
  - ~~Jak przetłumaczyć wzorzec katalogowy `katalog/` i negacje?~~ Rozstrzygnięte 2026-08-04: dopasowaniem zajmuje się `gix-ignore` / `gix-glob`, więc semantyka jest dosłownie taka jak w `.gitignore`; negacje obsługiwane, ostatnie dopasowanie wygrywa, a `status` wypisuje je osobno. Tłumaczenie na `katalog/**` zostaje potrzebne wyłącznie dla kosmetycznych linii `-text` / `diff`. — Właściciel: użytkownik. Blokuje: nie.
  - ~~Jakie zachowanie domyślne przy braku deklaracji EOL?~~ Rozstrzygnięte 2026-08-04: **`text=auto`**, czyli autorozpoznanie po treści jak w gicie. `.git-xcrypt` przejmuje **cały** słownik konwersji (`text`, `-text`, `binary`, `text=auto`, `eol=lf|crlf|native`), a atrybuty rozstrzygają się na osobnej osi niż selekcja ścieżek. — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** rozjazd konfiguracji dawał ciche nieszyfrowanie — najgroźniejszy tryb awarii w produkcie. Usunięty konstrukcyjnie, ale przeniósł ryzyko gdzie indziej: filtr działa teraz na **każdym** pliku repozytorium, więc błąd w przepuszczaniu treści uszkadza cały projekt, nie tylko sekrety. Stąd wymóg testu właściwości `passthrough(x) == x` już w `S-01`. Ujawnił się przy tym drugi rozjazd, przewidziany w opisie jako „kosmetyczny": wzorzec katalogowy w wygenerowanym `.gitattributes` sięgał płycej niż ten sam wzorzec w filtrze, więc `-text` gubiło się dokładnie na ścieżkach, które chroni. Ocena „błąd w tę stronę jest nieszkodliwy" była błędna.
- **Status:** done

### S-03: Przeniesienie repozytorium na drugą maszynę

- **Outcome:** użytkownik eksportuje klucz repozytorium do pliku, a po klonie na innej maszynie odblokowuje repozytorium tym plikiem i dostaje treść bajt w bajt identyczną z oryginałem.
- **Change ID:** key-export-and-unlock
- **PRD refs:** US-01, FR-007, FR-008
- **Prerequisites:** S-01
- **Parallel with:** S-02, S-05, S-07
- **Blockers:** —
- **Unknowns:**
  - Co chroni użytkownika przed utratą jedynego pliku klucza? Element zamknięty bez pełnej odpowiedzi — zaimplementowano odmowę cichego nadpisania istniejącego pliku klucza (`--force` jako jawna zgoda) i odmowę zapisu wewnątrz katalogu gita; kopia zapasowa pozostaje po stronie użytkownika. — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** komenda wydająca klucz to najkrótsza droga do wycieku — ścieżka zapisu musi wykluczać katalog repozytorium i standardowe wyjście. Element realizuje jedyną historyjkę użytkownika w PRD, więc jego niepowodzenie oznacza, że produkt nie rozwiązuje pierwotnego bólu. Przegląd pokazał, że najkrótsza droga nie prowadziła przez samą komendę: przewidywalna nazwa pliku tymczasowego otwieranego bez `O_EXCL` pozwalała podstawić dowiązanie i przekierować zapis klucza głównego gdzie indziej.
- **Status:** done

### S-04: Zamknięcie repozytorium

- **Outcome:** użytkownik zamyka odblokowane repozytorium jedną komendą i pliki objęte wzorcami wracają w katalogu roboczym do postaci zaszyfrowanej.
- **Change ID:** lock-repository
- **PRD refs:** FR-009
- **Prerequisites:** S-03
- **Parallel with:** —
- **Blockers:** —
- **Unknowns:**
  - ~~Co chroni przed zamknięciem repozytorium bez wcześniejszego wyeksportowania klucza?~~ Rozstrzygnięte 2026-08-04: `lock` domyślnie interaktywny z potwierdzeniem `yes`, flaga `--yes` na tryb nieinteraktywny, ostrzeżenie w obu trybach z `key_id` (nigdy z kluczem), plus odmowa przy niezacommitowanych zmianach, której `--yes` nie obchodzi. Patrz `zalozenia.md` §Zarządzanie kluczami → „Zabezpieczenia `lock`". — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** jedna komenda może odciąć użytkownika od całej historii własnych sekretów. Rzadko używana ścieżka o wysokim koszcie błędu jest jednocześnie tą najsłabiej przetestowaną w praktyce — stąd zabezpieczenia są dwa i osobne, bo utrata klucza i utrata niezacommitowanych zmian to różne ryzyka. Potwierdzone w praktyce: oba przebiegi przeglądu znalazły ścieżki kończące się usuniętym kluczem nad jawnym katalogiem roboczym, w tym dwie w podłączonych worktree — trzeci checkout czytający ten sam klucz nie był przewidziany ani w planie, ani w `zalozenia.md`.
- **Status:** done

### S-05: Różnice na treści odszyfrowanej

- **Outcome:** użytkownik ogląda różnice między wersjami pliku na treści jawnej zamiast na szumie ciphertextu.
- **Change ID:** decrypted-diff
- **PRD refs:** FR-006
- **Prerequisites:** S-01
- **Parallel with:** S-02, S-03, S-07
- **Blockers:** —
- **Unknowns:** —
- **Risk:** to trzecia ścieżka deszyfrowania obok szyfrowania przy commicie i odszyfrowywania przy checkoucie — musi dzielić kod z pozostałymi, inaczej rozjedzie się z formatem przy pierwszej jego zmianie. Jedyny element bez własnej niewiadomej, więc dobry kandydat na pracę równoległą, gdy reszta czeka na decyzje. Brak niewiadomej nie znaczył braku niespodzianki: zmierzono, że `textconv` dostaje **plaintext**, bo git materializuje obie strony różnicy przez smudge, zanim poda je sterownikowi — wbrew założeniu planu. Konsekwencja weszła do `lock`, który musi wyrejestrować sterownik, inaczej w repozytorium bez klucza `git log -p` przerywa się na zadeklarowanej ścieżce.
- **Status:** done

### S-06: Widoczność stanu szyfrowania

- **Outcome:** użytkownik sprawdza jedną komendą, czy konfiguracja jest kompletna i czy pliki dziś szyfrowane nie występowały kiedyś w repozytorium jawnie — a to, co da się naprawić bezpiecznie, naprawia flagą `--fix`.
- **Change ID:** encryption-status-check
- **PRD refs:** FR-010
- **Prerequisites:** S-02
- **Parallel with:** —
- **Blockers:** —
- **Zakres doprecyzowany 2026-08-04:** cztery zadania — kompletność `filter.git-xcrypt.*` w `.git/config`, skan całej osiągalnej historii po 11 bajtach magic, `--fix` ponownie dodający pliki leżące jawnie w `HEAD`/indeksie oraz ostrzeżenie na ścieżce filtra przy pierwszym szyfrowaniu pliku, który już leży w `HEAD` jawnie (implementowane w filtrze, ale należy do tego elementu). Kod wyjścia `5` przy znalezisku, do użycia jako bramka CI. Czyszczenie historii **nie wchodzi** — komenda raportuje ekspozycję i wypisuje procedurę, w której rotacja sekretu wyprzedza przepisanie historii.
- **Unknowns:**
  - ~~Jak głęboko sprawdzać repozytorium — tylko bieżący stan czy całą historię?~~ Rozstrzygnięte 2026-08-04: **cała osiągalna historia**. Przesłanka o koszcie okazała się słaba — skan nie deszyfruje, czyta 11 bajtów na blob o pasującej ścieżce, więc koszt zależy od liczby obiektów, nie od ich rozmiaru. — Właściciel: użytkownik. Blokuje: nie.
  - ~~Czy skan historii ma odpalać się automatycznie przy dopisaniu nowego wzorca?~~ Rozstrzygnięte 2026-08-04: pełny skan zostaje ręczny (`status`) i w CI, a automatyczne jest **tanie ostrzeżenie na ścieżce filtra** — przy pierwszym szyfrowaniu pliku jeden odczyt obiektu sprawdza, czy ta sama ścieżka leży w `HEAD` jawnie. Filtr to jedyny mechanizm działający niezależnie od klienta; hak `pre-commit` odpada. — Właściciel: użytkownik. Blokuje: nie.
  - Czy `stderr` filtra jest wystarczająco widoczny w oknie narzędziowym Git w JetBrains, żeby ostrzeżenie nie ginęło? **Nadal nierozstrzygnięte po zamknięciu elementu** — wymaga człowieka przy otwartym RustRoverze, nie da się sprawdzić automatycznie i nie zgadujemy (`plan.md` krok 3.9). Element zamknięty mimo to, bo ostrzeżenie działa niezależnie od klienta. — Właściciel: —. Blokuje: nie.
- **Risk:** płytkie sprawdzenie dawałoby fałszywe poczucie bezpieczeństwa i byłoby gorsze niż brak komendy — dlatego głębokość jest pełna. Zostaje ryzyko komunikacyjne: `--fix` naprawia wyłącznie przyszłość, a użytkownik może odczytać „naprawiono" jako „sekret jest bezpieczny". Treść komunikatów jest tu częścią zabezpieczenia, nie kosmetyką. Największe znalezisko przeglądu leżało gdzie indziej: skan historii zakładał SHA-1, a magazyn obiektów asertuje rodzaj skrótu — w repozytorium SHA-256 paniką wywracało się nie tylko `status`, ale i filtr na ścieżce check-in, więc przy `required = true` padała każda operacja gita.
- **Status:** done

### S-07: Gotowa binarka dla trzech platform

- **Outcome:** użytkownik pobiera plik wykonywalny dla Windows, macOS lub Linuksa i używa go bez kompilowania i bez instalowania dodatkowych bibliotek.
- **Change ID:** cross-platform-binaries
- **PRD refs:** FR-011, §Non-Functional Requirements (identyczne zachowanie na trzech platformach)
- **Prerequisites:** S-01 (zrobiony), S-08 (zrobiony 2026-08-04 — wymagany termin „przed pierwszym wydaniem” dotrzymany)
- **Parallel with:** —
- **Blockers:** —
- **Zakres zrobiony w przeglądzie końcowym (2026-08-04, runda 3):** infrastruktura tego elementu jest już w repozytorium, bo zamyka luki pokrycia zgłoszone przez dwa poprzednie przeglądy, a nie dlatego, że element został wzięty do realizacji.
  - `.github/workflows/ci.yml` — `cargo test --all-targets` na ubuntu/macOS/Windows, `fmt --check`, `clippy --all-targets -- -D warnings`, `cargo audit`, `cargo deny check licenses advisories sources bans`, plus zadanie `msrv`.
  - `.github/workflows/release.yml` — pięć targetów (Linux musl x86_64/aarch64, macOS x86_64/aarch64, Windows MSVC), pakowanie z sumami SHA-256, publikacja przy tagu `v*`, sprawdzenie zgodności tagu z `Cargo.toml`.
  - `deny.toml` — polityka licencyjna; jedyne odstępstwa od pary MIT/Apache przyjęte świadomie to `Zlib` (`zlib-rs`) i `BSD-3-Clause` (`subtle`). Zweryfikowana uruchomieniem: `advisories ok, bans ok, licenses ok, sources ok`.
  - `Cargo.toml` — komplet metadanych publikacyjnych, `rust-version = "1.88"` (zmierzone: na 1.85 crate się nie kompiluje) i profil `release`.
- **Zakres pozostały:** sama publikacja — tap Homebrew, publikacja na crates.io, pierwszy tag `v0.1.0`. Podpisywanie artefaktów **odpadło z tej listy 2026-08-05**: `release.yml` atestuje każde archiwum przez `actions/attest-build-provenance`, a decyzja i jej koszty są zapisane w `zalozenia.md` §Otwarte decyzje poz. 14. Odtwarzalność builda zostaje świadomie otwarta i **nie jest** warunkiem wydania. Sam krok atestacji nie był jeszcze wykonany przez GitHub Actions — uruchamia się dopiero przy tagu `v*`, więc pierwszy przebieg wydania jest jednocześnie jego pierwszym sprawdzeniem.
- **Unknowns:**
  - ~~Jaka nazwa crate'a i binarki wobec kolizji z oryginalnym `git-crypt` w menedżerach pakietów?~~ Rozstrzygnięte 2026-08-04: `git-xcrypt`. — Właściciel: użytkownik. Blokuje: nie.
  - ~~Jaka licencja projektu wobec GPL-3.0 projektów inspirujących?~~ Rozstrzygnięte 2026-08-04: `MIT OR Apache-2.0`, teksty licencji w repozytorium. — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** publikacja pod kolidującą nazwą albo bez rozstrzygniętej licencji jest trudna do wycofania — obie decyzje musiały zapaść przed pierwszym publicznym wydaniem i zapadły 2026-08-04. Sama technika jest tu najprostsza w całej roadmapie; pozostaje pilnować, by `cargo deny check licenses` w CI nie wpuściło zależności copyleft, która unieważniłaby wybór.
- **Status:** proposed

### S-08: Zgodność wykrywania plików binarnych z gitem

- **Outcome:** plik, który git uznaje za tekst, git-xcrypt też uznaje za tekst — łącznie z plikiem zakończonym DOS-owym znacznikiem końca `SUB` (`0x1A`), który rozjeżdżał się z gitem do 2026-08-04.
- **Change ID:** binary-detection-parity
- **PRD refs:** §Non-Functional Requirements (identyczne zachowanie na trzech platformach), §Guardrails (filtr nie uszkadza pliku użytkownika)
- **Prerequisites:** S-01 (zrobiony)
- **Parallel with:** —
- **Blockers:** —
- **Termin wiążący — dotrzymany.** Element zamknięty 2026-08-04, przed `S-07`, czyli przed pierwszym publicznym wydaniem binarki. `looks_binary` jest zamrożony razem z formatem (`src/eol.rs:47`) — dopóki nie istnieje ani jedno repozytorium poza tym projektem, poprawka kosztuje jedną linię; po wydaniu kosztuje nowy `suite`, bo przesuwa granicę tekst/binarny i przepisuje ciphertext istniejących plików.
- **Znalezisko (2026-08-04, review `looks_binary`):** `gather_stats` w `convert.c` gita v2.55.0 kończy się korektą, której nasz port nie ma:
  ```c
  /* If file ends with EOF then don't count this EOF as non-printable. */
  if (size >= 1 && buf[size-1] == '\032')
          stats->nonprintable--;
  ```
  Zweryfikowane na żywym gicie 2.55, nie tylko z lektury źródeł: repozytorium tymczasowe, `* text=auto`, plik o treści `a\r\n\x1a` → blob `61 0a 1a`, czyli git **znormalizował CRLF**, więc uznał plik za tekst. Nasz `looks_binary` na tej samej treści liczy `printable = 1`, `nonprintable = 1`, `0 < 1` → **binarny**. Granica text/binary leży u nas o jeden bajt bliżej niż u gita.
- **Zakres — zrobiony 2026-08-04:**
  - korekta w `src/eol.rs::looks_binary` — po pętli zdejmowany jest jeden `nonprintable`, gdy `content.last() == Some(&0x1a)`; `saturating_sub`, bo panic w debug przerywa operację gita, a nie tylko test;
  - `eol::tests::a_trailing_sub_is_forgiven_exactly_as_git_forgives_it` — dokładnie ta treść i granice korekty (dwa `SUB`, `SUB` w środku, `SUB` zużyty przez `0x01`, granica 128 : 127, `SUB` bez CR sprawdzony przez checkout);
  - osiem nowych wektorów w `tests/format_vectors.rs::binary_verdicts`, więc reguła jest zamrożona razem z formatem, a nie tylko przetestowana;
  - `tests/filter_edge_cases.rs::a_dos_end_of_file_marker_is_classified_the_way_git_classifies_it` — porównanie z **prawdziwym gitem** na czterech kształtach: repozytorium referencyjne z `* text=auto` daje werdykt, nasz blob musi mieć ten sam bit `flags` i ten sam rozmiar plaintextu;
  - granica proporcji miała już wektor (`the_ratio_sits_exactly_where_gits_does`, przegląd 3), rozszerzony teraz o parę z korektą `SUB`;
  - `zalozenia.md` §Końce linii → „Zmierzone zachowanie gita" uzupełnione: reguła ma sześć punktów i zdanie mówiące, że zamraża się od 2026-08-04, a nie wcześniej.
- **Sprawdzone przy okazji i zgodne — nie ruszać:** lone `CR` (w tym `CR` na końcu bufora), `CR`/`LF` w żadnym kubełku, `DEL` (`0x7f`) jako non-printable, wybaczone wyłącznie `BS`/`TAB`/`FF`/`ESC`, `≥ 0x80` jako printable, `printable >> 7`, skan całej treści (okno 8000 B należy do `mmfile_is_binary` w `diff.c`, nie tutaj). Port jest wierny — brakowało wyłącznie korekty na `SUB`, i to jest jedyne, co ten element zmienił.
- **Unknowns — nierozstrzygnięte przy zamknięciu:**
  - Czy przy tej okazji domykamy otwartą decyzję 8 z `zalozenia.md` (odpowiednik `core.safecrlf`)? **Nie domknięte** — zostaje otwarte, bo dotyczy ostrzegania, nie parytetu werdyktu, i nie zamraża się z formatem. Powiązanie jest realne: jawny `text` omija ochronę lone-`CR` — zgodnie z gitem, bo `crlf_to_git` konsultuje `convert_is_binary` tylko dla wariantów `CRLF_AUTO*` — więc treść `a\r\r\nb` daje jeden fałszywy „modified" po checkoucie, zanim stan się ustabilizuje. Test `content_that_is_normalised_survives_a_second_pass` pokrywa dziś tylko `Auto`, więc ta dziura nie jest nawet oznaczona testem. — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** rozjazd dotyczy wąskiej klasy plików (stare pliki tekstowe z DOS-a), więc kusił, żeby go odłożyć — i to była właśnie pułapka. Koszt nie rósł liniowo, tylko skoczyłby w momencie pierwszego wydania, bo reguła jest zamrożona z formatem. Sama poprawka to jedna linia; kosztowne byłoby jej przegapienie przed `S-07`.
- **Status:** done

## Backlog Handoff

Do wzięcia został jeden element: `S-07`. `S-08` zamknięty 2026-08-04, w wymaganej kolejności — reguła tekst/binarny zamraża się z pierwszym publicznym wydaniem, więc musiał wejść wcześniej.

| Roadmap ID | Change ID                    | Sugerowany tytuł zadania                            | Gotowe do `/10x-plan` | Uwagi                                       |
| ---------- | ---------------------------- | --------------------------------------------------- | --------------------- | ------------------------------------------- |
| S-08       | binary-detection-parity      | Zgodność wykrywania plików binarnych z gitem        | zrobione              | Zamknięte 2026-08-04, przed `S-07` — termin dotrzymany |
| S-07       | cross-platform-binaries      | Binarki dla Windows, macOS i Linuksa                | tak                   | **Jedyny otwarty element** — `S-08` zamknięty, więc nic go już nie blokuje. CI, pipeline wydania i metadane publikacyjne powstały przy przeglądzie końcowym, podpisywanie rozstrzygnięte 2026-08-05 na atestacje GitHuba; zostaje tap Homebrew, crates.io i pierwszy tag |
| F-01       | git-integration-test-harness | Harness testów na prawdziwym repozytorium git       | zrobione              | Zarchiwizowane 2026-08-04                   |
| S-01       | transparent-encrypt-decrypt  | Przezroczyste szyfrowanie w jednym repozytorium     | zrobione              | Zaimplementowane i przejrzane dwukrotnie 2026-08-04 |
| S-02       | gitignore-style-config       | Konfiguracja w składni .gitignore                   | zrobione              | Zaimplementowane i przejrzane dwukrotnie 2026-08-04 |
| S-03       | key-export-and-unlock        | Eksport klucza i odblokowanie po klonie             | zrobione              | Zaimplementowane i przejrzane dwukrotnie 2026-08-04 |
| S-04       | lock-repository              | Zamknięcie repozytorium                             | zrobione              | Zaimplementowane i przejrzane dwukrotnie 2026-08-04 |
| S-05       | decrypted-diff               | Różnice na treści odszyfrowanej                     | zrobione              | Zaimplementowane i przejrzane dwukrotnie 2026-08-04 |
| S-06       | encryption-status-check      | Widoczność stanu szyfrowania                        | zrobione              | Zaimplementowane i przejrzane dwukrotnie 2026-08-04 |

## Open Roadmap Questions

1. ~~**Jak nie dopuścić do rozjazdu pliku konfiguracyjnego i konfiguracji czytanej przez gita?**~~ Rozstrzygnięte 2026-08-04: konstrukcja catch-all, `.git-xcrypt` jedynym źródłem prawdy, filtr długożyjący jako warunek wykonalności. Patrz `prd.md` §Open Questions poz. 1 i `zalozenia.md` §Integracja z git. — Właściciel: użytkownik. Blokuje: nic.
2. ~~**Co chroni przed zamknięciem repozytorium bez wcześniejszego wyeksportowania klucza?**~~ Rozstrzygnięte 2026-08-04: potwierdzenie interaktywne, ostrzeżenie z `key_id` zamiast klucza, odmowa przy brudnym katalogu roboczym. — Właściciel: użytkownik. Blokuje: nic.
3. ~~**Jak głęboko `status` sprawdza repozytorium — bieżący stan czy cała historia?**~~ Rozstrzygnięte 2026-08-04: cała osiągalna historia, plus `--fix` na naprawę bezpieczną i kod wyjścia `5` przy znalezisku. — Właściciel: użytkownik. Blokuje: nic.
4. ~~**Jaka nazwa crate'a i binarki wobec kolizji z oryginalnym `git-crypt`?**~~ Rozstrzygnięte 2026-08-04: `git-xcrypt` dla crate'a i binarki. — Właściciel: użytkownik. Blokuje: nic.
5. ~~**Jaka licencja projektu wobec GPL-3.0 projektów inspirujących?**~~ Rozstrzygnięte 2026-08-04: `MIT OR Apache-2.0` dla crate'a i binarki. — Właściciel: użytkownik. Blokuje: nic.
6. **Co chroni użytkownika przed utratą jedynego pliku klucza?** — **zakres rozstrzygnięty 2026-08-04, pytanie zostaje otwarte na przyszłość.** W v0.1 mechanizmu kopii zapasowej nie ma i nie będzie: obowiązek leży po stronie użytkownika, a rozwiązaniem jest dokumentacja — sekcja „The key file is the only copy — back it up yourself" w `README.md` plus wpis w §Known limitations. Przypomnienie w `init` rozważone i odrzucone. Zaimplementowane zabezpieczenia (`export-key` z komunikatem i odmową zapisu w repozytorium, `lock` z potwierdzeniem `yes`, `key_id`, odmową przy niezacommitowanych zmianach i przy innych worktree) zostają opisane jako progi zwalniające, nie jako kopia. Patrz `prd.md` §Open Questions poz. 2. — Owner: użytkownik. Blokuje: nic.
7. **Jaki jest liczbowy próg dla wymagania wydajnościowego?** — Właściciel: użytkownik. Blokuje: nic; wpływa na ocenę gotowości v0.1 — bez liczby nie da się stwierdzić, czy wymaganie zostało spełnione, choć sześć elementów przeszło mimo braku progu.
8. **Czy któreś wymaganie ma być opcjonalne zamiast koniecznego?** — Właściciel: użytkownik. Blokuje: nic; wpływa na ocenę gotowości v0.1. Wszystkie 11 wymagań przyjęto jako konieczne domyślnie, bez potwierdzenia.
9. ~~**Czy wiele kluczy w jednym repozytorium i rotacja klucza są poza zakresem?**~~ Rozstrzygnięte — oba są wymienione w `zalozenia.md` §Zakres MVP / poza zakresem jako **poza zakresem v0.1** („Wiele niezależnych kluczy w jednym repo (`--key-name`)" oraz „Rotacja klucza i wycofywanie dostępu odbiorcy z przepisaniem historii"). Format pliku jest na oba gotowy przez `key_id`. — Właściciel: użytkownik. Blokuje: nic.
10. **Czy pozostałe wymagania dostaną własne historyjki użytkownika?** — Właściciel: użytkownik. Blokuje: nic; wpływa na jakość kryteriów akceptacji w `S-02`, `S-03`, `S-04`, `S-06`.

## Parked

- **Zarządzanie odbiorcami i praca zespołowa** — Dlaczego: PRD §Non-Goals; model jest jednoosobowy, klucz przenoszony plikiem.
- **Kompatybilność z repozytoriami oryginalnego git-crypt** — Dlaczego: PRD §Non-Goals; własny format bez ścieżki migracji.
- **Ukrywanie metadanych** — Dlaczego: PRD §Non-Goals; nazwy plików, rozmiary i fakt zmiany pozostają jawne z założenia konstrukcji.
- **Ochrona przed skompromitowaną maszyną** — Dlaczego: PRD §Non-Goals; po odblokowaniu sekrety leżą jawnie na dysku.
- **Natywne czyszczenie historii (`purge-history`)** — Dlaczego: rozstrzygnięte 2026-08-04. Własny odpowiednik `git-filter-repo` w Ruście to element wielkości `S-01` (wywołanie zewnętrznego narzędzia odpada przez wymóg samowystarczalnej binarki), a operacja i tak nie cofa wycieku — sekret zostaje w forkach, cache'ach i cudzych klonach. W v0.1 `S-06` raportuje ekspozycję i wypisuje procedurę zaczynającą się od rotacji sekretu.

## Done

- **F-01: (foundation) weryfikować zachowanie na prawdziwym repozytorium git** — Zarchiwizowano 2026-08-04 → `context/archive/2026-08-04-git-integration-test-harness/`. Lekcja: —.
- **S-01: commitować plik i dostać ciphertext w repo, plaintext w katalogu roboczym** — Zarchiwizowano 2026-08-04 → `context/archive/2026-08-04-transparent-encrypt-decrypt/` (status `archived`, dwa przebiegi przeglądu). Lekcja: ładunek protokołu pkt-line to bajty, nie tekst — każde przejście ścieżki przez `String` albo przez `trim_end()` przesuwało plik na inny wzorzec i przepuszczało plaintext przy `git add` z kodem `0`. Drugi przebieg znalazł błąd wprowadzony przez naprawę z pierwszego, więc jeden przebieg by nie wystarczył.
- **S-02: wskazać pliki do szyfrowania w składni `.gitignore`** — Zarchiwizowano 2026-08-04 → `context/archive/2026-08-04-gitignore-style-config/` (status `archived`, dwa przebiegi przeglądu). Lekcja: „linia kosmetyczna" to ocena, nie fakt — wzorzec katalogowy generowany do `.gitattributes` sięgał płycej niż ten sam wzorzec w filtrze, więc `-text` znikało dokładnie tam, gdzie chroni ciphertext przed `core.autocrlf`. Każdy werdykt trzeba było sprawdzić przeciw `git check-attr`, nie przeciw własnemu rozumieniu składni.
- **S-03: odzyskać sekrety po klonie na drugiej maszynie** — Zarchiwizowano 2026-08-04 → `context/archive/2026-08-04-key-export-and-unlock/` (status `archived`, dwa przebiegi przeglądu). Lekcja: dwa moduły zapisujące pliki atomowo rozjechały się w tym, co robią bezpiecznie — ten, którym szedł klucz główny, otwierał przewidywalną nazwę bez `O_EXCL`, więc dawał się podstawić dowiązaniem. Jeden wzorzec zapisu na cały projekt, nie dwa podobne.
- **S-04: zamknąć odblokowane repozytorium z powrotem** — Zarchiwizowano 2026-08-04 → `context/archive/2026-08-04-lock-repository/` (status `archived`, dwa przebiegi przeglądu). Lekcja: sprawdzenie i zapis muszą patrzeć na tę samą treść — między dowodem „to już jest blobem" a szyfrowaniem leżało czekanie na odpowiedź człowieka, czyli okno bez ograniczenia. Osobno: klucz jest wspólny dla wszystkich worktree, a przejście po drzewie widzi jeden checkout; ta ścieżka nie była przewidziana ani w planie, ani w `zalozenia.md`.
- **S-05: oglądać różnice na treści jawnej** — Zarchiwizowano 2026-08-04 → `context/archive/2026-08-04-decrypted-diff/` (status `archived`, dwa przebiegi przeglądu). Lekcja: założenie planu o tym, co git podaje sterownikowi `textconv`, było błędne i wyszło dopiero z pomiaru — sterownik dostaje plaintext, bo obie strony różnicy przechodzą wcześniej przez smudge. Druga lekcja: nazwa pliku jest wejściem od użytkownika także dla naszego własnego parsera argumentów — plik `--help` kazał gitowi wyrenderować tekst pomocy jako treść.
- **S-06: sprawdzić, co jest szyfrowane, a co powinno być** — Zarchiwizowano 2026-08-04 → `context/archive/2026-08-04-encryption-status-check/` (status `archived`, dwa przebiegi przeglądu plus sondy na repozytoriach nietypowych: SHA-256, podzielony indeks, paczki, podłączony worktree, bare, płytki klon). Lekcja: domyślne wartości bibliotek gitoxide zakładają SHA-1 i asertują — w repozytorium SHA-256 panika sięgała nie tylko komendy, ale i filtra na ścieżce check-in, więc przy `required = true` przewracała każdą operację gita. Nierozstrzygnięte przy zamknięciu: widoczność `stderr` filtra w oknie Git w JetBrains.
- **S-08: dostać ten sam werdykt tekst/binarny co git, także na pliku z `SUB`** — Ukończono 2026-08-04, **przed `S-07`**, czyli w wymaganym terminie: `looks_binary` zamraża się z pierwszym publicznym wydaniem, więc po nim ta jedna linia przestałaby być poprawką, a stałaby się zmianą przepisującą ciphertext istniejących plików i wymagającą nowego `suite`. Lekcja: parytet z gitem trzeba weryfikować wobec **całej** funkcji źródłowej — brakująca korekta siedziała w trzech ostatnich liniach `gather_stats`, za pętlą, którą port odtwarzał wiernie. Wektory formatu tego nie łapały: żaden z istniejących nie kończył się bajtem `0x1A`.

Po zamknięciu `S-06` całość przeszła przez przegląd końcowy w trzech rundach. Raporty nie są już wersjonowane — ich treść odtwarza `git show <sha>` z commitów, które je wprowadziły:

- **runda 1, warstwa kryptograficzna i format** (`40a15b1`) — wyciek klucza głównego przez `git-xcrypt diff` na wyeksportowanym pliku z komentarzami, dwa testy `required = true`, które same sobie ustawiały tę flagę, i zamrożony format pliku klucza bez ani jednego wektora.
- **runda 2, integracja z gitem** (`53240f2`) — osiem znalezisk, w tym `required =` z pustą wartością czytane przez gita jako `false`, `export-key` piszący do sąsiedniego checkoutu i skan historii pomijający refy innych worktree.
- **runda 3, kompletność i jakość** (`775705c`) — scenariusz akceptacyjny jako jeden test z prawdziwym `push`, testy właściwości na `proptest`, CI na trzech platformach, `deny.toml`, metadane publikacyjne, zmierzony MSRV 1.88 oraz dwie mutacje przechodzące zielono, zamknięte testami.

Cztery decyzje właściciela wynikłe z tych rund wykonano w `87736eb`, `7fb6707`, `eae1049` i `33d3081`; ich zapis powstał w `20e0cc7`.
