---
project: "git-xcrypt"
version: 1
status: active
created: 2026-08-03
updated: 2026-08-07
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
| S-07  | cross-platform-binaries      | pobrać gotową binarkę dla swojej platformy                               | S-01, S-08    | FR-011                 | done     |
| S-08  | binary-detection-parity      | dostać ten sam werdykt tekst/binarny co git, także na pliku z `SUB`     | S-01          | §NFR (trzy platformy)  | done     |
| S-09  | per-user-keys                | otworzyć sklonowane repozytorium **własnym** kluczem, bez przenoszenia klucza repozytorium | S-03          | §Access Control, FR-008 | todo     |

## Streams

Pomoc nawigacyjna — grupuje elementy dzielące łańcuch wymagań wstępnych. Kanoniczna kolejność jest w grafie zależności niżej.

| Stream | Temat                    | Łańcuch                              | Uwaga                                                                        |
| ------ | ------------------------ | ------------------------------------ | ---------------------------------------------------------------------------- |
| A      | Rdzeń szyfrowania        | `F-01` → `S-01` → `S-03` → `S-04`    | Ścieżka gwiazdy przewodniej; niosła całe ryzyko techniczne celu `learn`. **Zamknięta 2026-08-04** — cały łańcuch zrobiony i przejrzany. |
| B      | Konfiguracja i widoczność | `S-02` → `S-06`                      | Dołącza do Strumienia A w `S-01`. **Zamknięta 2026-08-04** — obie decyzje (rozjazd konfiguracji, głębokość skanu) zapadły i są zaimplementowane. |
| C      | Narzędzia pracy          | `S-05`                               | Dołącza do A w `S-01`. **Zamknięta 2026-08-04**; jedyny element bez własnej niewiadomej — ale plan i tak trafił w błędne założenie o `textconv`, sprostowane pomiarem. |
| D      | Dystrybucja              | `S-08` → `S-07`                      | **Zamknięta 2026-08-07** wydaniem `v0.1.0`. `S-08` wszedł 2026-08-04, czyli w wymaganej kolejności: `looks_binary` zamraża się z pierwszym publicznym wydaniem. Nazwa i licencja rozstrzygnięte 2026-08-04. Poza tagiem zostają świadomie crates.io i tap Homebrew — kanały dystrybucji, nie warunki wydania. |
| E      | Klucze użytkowników      | `S-03` → `S-09`                      | **Poza v0.1.** Pierwszy element, który zmienia model produktu, a nie dokłada do niego funkcję: dziś tożsamością jest sam klucz repozytorium. Format danych jest gotowy i nie wchodzi do zakresu. |

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
  - `deny.toml` — polityka licencyjna; jedyne odstępstwo od pary MIT/Apache przyjęte świadomie to `Zlib` (`zlib-rs`); `BSD-3-Clause` stało obok dla `subtle`, którego po bumpie `aes-siv` na 0.8 (2026-08-11) w grafie nie ma. Zweryfikowana uruchomieniem: `advisories ok, bans ok, licenses ok, sources ok`.
  - `Cargo.toml` — komplet metadanych publikacyjnych, `rust-version = "1.88"` (zmierzone: na 1.85 crate się nie kompiluje) i profil `release`.
- **Zakres pozostały:** sama publikacja — tap Homebrew, publikacja na crates.io, pierwszy tag `v0.1.0`. Podpisywanie artefaktów **odpadło z tej listy 2026-08-05**: `release.yml` atestuje każde archiwum przez `actions/attest-build-provenance`, a decyzja i jej koszty są zapisane w `zalozenia.md` §Otwarte decyzje poz. 14. Odtwarzalność builda **nie była** warunkiem wydania, a od 2026-08-11 jest **odrzucona** decyzją właściciela — patrz `zalozenia.md` §Otwarte decyzje poz. 14. **Sprostowanie z 2026-08-07:** stojące tu wcześniej zdanie, że sam krok atestacji nie był jeszcze wykonany przez GitHub Actions i że pierwszy przebieg wydania będzie jednocześnie jego pierwszym sprawdzeniem, było **nieprawdziwe**. `release.yml` ma ścieżkę `workflow_dispatch` właśnie po to, żeby ćwiczyć ten krok bez tagu, i została użyta dwa razy: przebieg `31029073064` (2026-08-05) i `31190705997` (2026-08-07), oba z komunikatem `Attestation created for 5 subjects`. Ten drugi doprowadzono do końca po stronie odbiorcy: pobrane archiwum `aarch64-apple-darwin` przechodzi `gh attestation verify … --repo rkarpin1/git-xcrypt` kodem `0`, a atestacja wiąże je z commitem `b6c4a5e` i z `.github/workflows/release.yml`; suma `.sha256` zgadza się z przeliczoną, a binarka z archiwum uruchamia się i podaje `git-xcrypt 0.1.0`. **Czego dispatch nie ćwiczy**, i to jest granica tej próby: zadanie `verify-version` jest pominięte warunkiem na tag, a nazwa archiwum bierze się z `GITHUB_REF_NAME`, czyli przy dispatchu z nazwy gałęzi (`git-xcrypt-master-…`) — poprawną nazwę z `v0.1.0` da dopiero prawdziwy tag.
- **Unknowns:**
  - ~~Jaka nazwa crate'a i binarki wobec kolizji z oryginalnym `git-crypt` w menedżerach pakietów?~~ Rozstrzygnięte 2026-08-04: `git-xcrypt`. — Właściciel: użytkownik. Blokuje: nie.
  - ~~Jaka licencja projektu wobec GPL-3.0 projektów inspirujących?~~ Rozstrzygnięte 2026-08-04: `MIT OR Apache-2.0`, teksty licencji w repozytorium. — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** publikacja pod kolidującą nazwą albo bez rozstrzygniętej licencji jest trudna do wycofania — obie decyzje musiały zapaść przed pierwszym publicznym wydaniem i zapadły 2026-08-04. Sama technika jest tu najprostsza w całej roadmapie; pozostaje pilnować, by `cargo deny check licenses` w CI nie wpuściło zależności copyleft, która unieważniłaby wybór.
- **Wydane 2026-08-07: tag `v0.1.0`, przebieg `31211254819`.** Wszystkie siedem zadań zielone, w tym `verify-version` (tag zgodny z `Cargo.toml`), którego próba `workflow_dispatch` nie ćwiczy. Opublikowane dziesięć artefaktów: pięć archiwów (`aarch64`/`x86_64` macOS, `aarch64`/`x86_64` Linux musl, `x86_64` Windows MSVC) i pięć sum SHA-256. Sprawdzone jako odbiorca, nie założone: pobrane archiwum przechodzi `shasum -a 256 -c` i `gh attestation verify … --repo rkarpin1/git-xcrypt` kodem `0`, atestacja wiąże je z `refs/tags/v0.1.0` i commitem `56e130b`, a binarka z archiwum uruchamia się i podaje `git-xcrypt 0.1.0`.
- **Co z tego elementu zostaje otwarte, świadomie:** publikacja na crates.io (nazwa `git-xcrypt` nadal wolna; `cargo publish --dry-run` przechodzi — 60 plików, 320,6 KiB) oraz tap Homebrew (wymaga własnego repozytorium tapa). Żadne z nich nie było warunkiem wydania binarek, czyli tego, co obiecuje FR-011; obie są rozszerzeniem kanałów dystrybucji i mogą wejść bez tagu. Odtwarzalność builda **przestała być pozycją otwartą 2026-08-11** — odrzucona decyzją właściciela, z pomiarami i warunkami powrotu w `zalozenia.md` §Otwarte decyzje poz. 14. `README.md` nadal mówi wprost, że build nie jest odtwarzalny; zmienił się status pozycji, nie ostrzeżenie.
- **Status:** done

### S-08: Zgodność wykrywania plików binarnych z gitem

- **Outcome:** plik, który git uznaje za tekst, git-xcrypt też uznaje za tekst — łącznie z plikiem zakończonym DOS-owym znacznikiem końca `SUB` (`0x1A`), który rozjeżdżał się z gitem do 2026-08-04.
- **Change ID:** binary-detection-parity
- **PRD refs:** §Non-Functional Requirements (identyczne zachowanie na trzech platformach), §Guardrails (filtr nie uszkadza pliku użytkownika)
- **Prerequisites:** S-01 (zrobiony)
- **Parallel with:** —
- **Blockers:** —
- **Termin wiążący — dotrzymany.** Element zamknięty 2026-08-04, przed `S-07`, czyli przed pierwszym publicznym wydaniem binarki. `looks_binary` jest zamrożony razem z formatem (`src/rules/eol.rs:47`) — dopóki nie istnieje ani jedno repozytorium poza tym projektem, poprawka kosztuje jedną linię; po wydaniu kosztuje nowy `suite`, bo przesuwa granicę tekst/binarny i przepisuje ciphertext istniejących plików.
- **Znalezisko (2026-08-04, review `looks_binary`):** `gather_stats` w `convert.c` gita v2.55.0 kończy się korektą, której nasz port nie ma:
  ```c
  /* If file ends with EOF then don't count this EOF as non-printable. */
  if (size >= 1 && buf[size-1] == '\032')
          stats->nonprintable--;
  ```
  Zweryfikowane na żywym gicie 2.55, nie tylko z lektury źródeł: repozytorium tymczasowe, `* text=auto`, plik o treści `a\r\n\x1a` → blob `61 0a 1a`, czyli git **znormalizował CRLF**, więc uznał plik za tekst. Nasz `looks_binary` na tej samej treści liczy `printable = 1`, `nonprintable = 1`, `0 < 1` → **binarny**. Granica text/binary leży u nas o jeden bajt bliżej niż u gita.
- **Zakres — zrobiony 2026-08-04:**
  - korekta w `src/rules/eol.rs::looks_binary` — po pętli zdejmowany jest jeden `nonprintable`, gdy `content.last() == Some(&0x1a)`; `saturating_sub`, bo panic w debug przerywa operację gita, a nie tylko test;
  - ~~`eol::tests::a_trailing_sub_is_forgiven_exactly_as_git_forgives_it`~~ — **poprawka nazwy z 2026-08-06:** ten test, podobnie jak `the_ratio_sits_exactly_where_gits_does` niżej, **nie istnieje** od redukcji zestawu z 466 do 89 testów 2026-08-05. Reguła jest jednak pokryta i to mocniej, niż była: przeniesiono ją do zamrożonych wektorów, gdzie zmiana granicy tekst/binarny psuje test formatu, a nie tylko test jednostkowy. Sprawdzone, nie założone;
  - osiem wektorów w `tests/format_vectors.rs::binary_verdicts` — pokrywają dokładnie te granice, które opisywały usunięte testy: dwa `SUB`, `SUB` w środku, `SUB` zużyty przez `0x01` oraz obie strony progu proporcji (128 drukowalnych → tekst, 127 → binarny). Reguła jest więc zamrożona razem z formatem, a nie tylko przetestowana;
  - `tests/filter_edge_cases.rs::a_dos_end_of_file_marker_is_classified_the_way_git_classifies_it` — **żyje** i jest porównaniem z **prawdziwym gitem** na czterech kształtach: repozytorium referencyjne z `* text=auto` daje werdykt, nasz blob musi mieć ten sam bit `flags` i ten sam rozmiar plaintextu;
  - `zalozenia.md` §Końce linii → „Zmierzone zachowanie gita" uzupełnione: reguła ma sześć punktów i zdanie mówiące, że zamraża się od 2026-08-04, a nie wcześniej.
- **Sprawdzone przy okazji i zgodne — nie ruszać:** lone `CR` (w tym `CR` na końcu bufora), `CR`/`LF` w żadnym kubełku, `DEL` (`0x7f`) jako non-printable, wybaczone wyłącznie `BS`/`TAB`/`FF`/`ESC`, `≥ 0x80` jako printable, `printable >> 7`, skan całej treści (okno 8000 B należy do `mmfile_is_binary` w `diff.c`, nie tutaj). Port jest wierny — brakowało wyłącznie korekty na `SUB`, i to jest jedyne, co ten element zmienił.
- **Unknowns — nierozstrzygnięte przy zamknięciu:**
  - ~~Czy przy tej okazji domykamy otwartą decyzję 8 z `zalozenia.md` (odpowiednik `core.safecrlf`)?~~ **Domknięte 2026-08-06, osobno od tego elementu** — dotyczyło ostrzegania, nie parytetu werdyktu, więc nie musiało zdążyć przed wydaniem i nie zamroziło się z formatem. Rozstrzygnięcie: ostrzeżenie na `stderr` z filtra, predykat **węższy** niż gitowy (pyta, czy oryginał da się odtworzyć, a nie czy bajty się zmienią — inaczej zapalałby się na każdym pliku z samymi `LF` przy `core.autocrlf=true`). Zapis i pomiary: `zalozenia.md` §Otwarte decyzje poz. 8.
    - Dwa sprostowania do tego, co stało w tym wierszu wcześniej. **Kształt `a\r\r\nb` nie był jedynym** — mieszane `CRLF`+`LF` pod domyślnym `text=auto` tracą oryginał tak samo, i to groźniej, bo `git status` zostaje wtedy **czysty**. **A test `content_that_is_normalised_survives_a_second_pass` już nie istniał** w chwili pisania tamtej notatki — zniknął przy redukcji zestawu z 466 do 89 testów 2026-08-05. Odsyłanie do martwej nazwy jako do dowodu pokrycia jest dokładnie tym trybem awarii, przed którym broni zasada „usunięcie testu wymaga takiego samego dowodu jak dodanie strażnika". — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** rozjazd dotyczy wąskiej klasy plików (stare pliki tekstowe z DOS-a), więc kusił, żeby go odłożyć — i to była właśnie pułapka. Koszt nie rósł liniowo, tylko skoczyłby w momencie pierwszego wydania, bo reguła jest zamrożona z formatem. Sama poprawka to jedna linia; kosztowne byłoby jej przegapienie przed `S-07`.
- **Status:** done

### S-09: Obsługa kluczy użytkowników

- **Outcome:** użytkownik otwiera sklonowane repozytorium **własnym** kluczem prywatnym, zamiast przenosić na maszynę plik klucza repozytorium. Klucz repozytorium zostaje jeden, ale leży w katalogu `.git-xcrypt-keys/` zaszyfrowany osobno dla każdego uprawnionego.
- **Change ID:** per-user-keys
- **PRD refs:** §Access Control (dziś: „jeden ręczny transfer na maszynę"), FR-008
- **Prerequisites:** S-03 (zrobiony)
- **Parallel with:** —
- **Blockers:** — technicznych nie ma; to jest decyzja o zakresie produktu, nie o kolejności prac.
- **Zapisany 2026-08-11 na prośbę właściciela**, przeniesiony z `## Parked`. **To zapis zamiaru, nie harmonogram** — nic tu nie jest zaplanowane na konkretne wydanie. PRD wymienia zarządzanie odbiorcami w §Non-Goals, ale ten zapis dotyczy **v0.1**; element leży poza nią i nie jest z nim sprzeczny.
- **Co już istnieje, i jest tego mało:** zarezerwowana nazwa katalogu `.git-xcrypt-keys` (`src/git/repo.rs:17`), wraz z tym, że nigdy nie jest szyfrowany i że sekcja zarządzana renderuje mu wykluczenie. Ani jednej linii kopert.
- **Czego robić nie trzeba, i to jest tu najważniejsze:** **format pliku danych jest gotowy i nie zmienia się ani o bajt.** Koperta pakuje 32-bajtowy **klucz główny**, więc jest niezależna od suite'a i od formatu bloba, a `key_id` — w zamrożonym nagłówku, w AAD — identyfikuje właśnie klucz główny, więc wiele kluczy w jednym repozytorium i rotacja też mieszczą się bez nowego `suite`. Blob sam mówi, którym kluczem go otwierać.
- **Unknowns:**
  - **Format koperty: `age` czy `crypto_box`?** To jest otwarta decyzja 1 z `zalozenia.md` i jedyna, która blokuje start. Konflikt jest realny, bo obie strony łamią coś zapisanego: `age` (0.12.1, MIT OR Apache-2.0) jest interoperacyjny i mały, ale **spoza RustCrypto**; `crypto_box` (0.9.1 stabilne, 0.10.0-pre.0 w drodze, Apache-2.0 OR MIT) regułę „wyłącznie RustCrypto" spełnia, ale każe napisać **własny** format koperty — czyli dokładnie to, czego zabrania druga twarda reguła, „nie składamy własnych konstrukcji z prymitywów". — Właściciel: użytkownik. Blokuje: tak, start elementu.
  - **`sequoia-openpgp` odpada na licencji, i to jest fakt zmierzony 2026-08-11, którego `zalozenia.md` poz. 1 nie zna.** Wersja 2.4.1 jest na **LGPL-2.0-or-later**, a lista dozwolonych w `deny.toml` nie zawiera żadnego GPL ani LGPL — polityka istnieje właśnie po to, żeby copyleft nie wszedł bocznymi drzwiami z zależnością i nie unieważnił wyboru `MIT OR Apache-2.0`. Czyli odrzuciłoby ją własne CI, zanim ktokolwiek zmierzyłby zapowiadany „nakład i rozmiar binarki". Wraca do gry tylko wtedy, gdy właściciel świadomie otworzy politykę licencyjną. — Właściciel: użytkownik. Blokuje: nie (zawęża wybór do dwóch).
  - **Gdzie leży klucz prywatny użytkownika i jak trafia na drugą maszynę?** Dziś pojęcie tożsamości użytkownika **nie istnieje** — tożsamością jest sam klucz repozytorium. Koperty wymagają pary kluczy na osobę, więc problem transportu, który produkt świadomie zostawia użytkownikowi, przesuwa się o jeden poziom, a nie znika. Nierozstrzygnięte. — Właściciel: użytkownik. Blokuje: tak.
  - **Czy `add-user` / `list-users` to właściwy zestaw komend**, skoro nazwy pochodzą z `git-crypt`, a zasada projektu mówi „pozostałe komendy mają odpowiadać projektom źródłowym co do nazwy i zachowania". — Właściciel: użytkownik. Blokuje: nie.
- **Dwie własności do udokumentowania, obie sprzeczne z intuicją:** dodanie odbiorcy daje dostęp do **całej historii**, nie od momentu dodania, bo klucz repozytorium jest jeden i niezmienny; usunięcie odbiorcy **nie odbiera** dostępu do tego, co już sklonował, i wymaga rotacji klucza, która sama jest poza zakresem v0.1. Jedno i drugie musi stać w dokumentacji użytkownika, zanim ktokolwiek na tym polegnie.
- **Risk:** to jedyny element roadmapy, który zmienia **model produktu**, a nie dodaje do niego funkcję — persona z PRD to jeden deweloper na kilku maszynach, więc odbiorcy są raczej innym produktem zbudowanym na tym samym formacie niż brakującą częścią tego. Ryzyko drugie, tańsze do przeoczenia: koperta jest miejscem, w którym łatwo złożyć własną konstrukcję kryptograficzną, a to jest dokładnie ta klasa błędu, przed którą broni reguła „nigdy nie składamy konstrukcji z prymitywów". Wybór `crypto_box` czyni to ryzyko realnym i wymagałby zapisania go tak samo jawnie, jak zapisano ryzyko nieaudytowanego `aes-siv`.
- **Status:** todo

## Backlog Handoff

Backlog v0.1 jest **pusty** — `S-07` zamknięty 2026-08-07 wydaniem `v0.1.0`, jako ostatni. `S-08` wszedł przed nim 2026-08-04, w wymaganej kolejności: reguła tekst/binarny zamraża się z pierwszym publicznym wydaniem. Co zostało poza roadmapą v0.1: publikacja na crates.io i tap Homebrew (kanały dystrybucji), plus pozycje z `## Parked`.

**Poza v0.1 stoi dziś jeden element: `S-09`**, zapisany 2026-08-11. Nie jest gotowy do `/10x-plan` i nie jest zaplanowany na żadne wydanie — blokują go dwie nierozstrzygnięte niewiadome, format koperty i to, gdzie w ogóle mieszka klucz prywatny użytkownika.

| Roadmap ID | Change ID                    | Sugerowany tytuł zadania                            | Gotowe do `/10x-plan` | Uwagi                                       |
| ---------- | ---------------------------- | --------------------------------------------------- | --------------------- | ------------------------------------------- |
| S-09       | per-user-keys                | Obsługa kluczy użytkowników                         | **nie**               | Poza v0.1, zapisane 2026-08-11. Blokuje wybór formatu koperty (`age` kontra `crypto_box`) i brak pojęcia tożsamości użytkownika. Format danych gotowy, nie zmienia się |
| S-08       | binary-detection-parity      | Zgodność wykrywania plików binarnych z gitem        | zrobione              | Zamknięte 2026-08-04, przed `S-07` — termin dotrzymany |
| S-07       | cross-platform-binaries      | Binarki dla Windows, macOS i Linuksa                | zrobione              | Wydane 2026-08-07 tagiem `v0.1.0` (przebieg `31211254819`): pięć archiwów z sumami i atestacją, weryfikacja odbiorcy sprawdzona. Otwarte świadomie i poza wydaniem: crates.io, tap Homebrew |
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
7. ~~**Jaki jest liczbowy próg dla wymagania wydajnościowego?**~~ **Rozstrzygnięte 2026-08-06:** trzy budżety — **25 µs** na plik przepuszczany, **30 µs** na plik szyfrowany, **2 ns/bajt** na szyfr, mierzone jako minimum z 5 przebiegów. Egzekwuje `tests/performance.rs`, świadomie `#[ignore]` (liczby mają sens tylko w `--release`, a zmierzony rozrzut 11% zrobiłby z tego migotliwą bramkę CI). Zapis i uzasadnienie: `prd.md` §Non-Functional Requirements oraz §Open Questions poz. 5. — Właściciel: użytkownik. Blokuje: nic.
8. **Czy któreś wymaganie ma być opcjonalne zamiast koniecznego?** — **odłożone świadomie 2026-08-06: pomijamy.** Wszystkie 11 dostarczone, więc zmiana priorytetu nie zdjęłaby pracy; zostaje zastrzeżenie, że `must-have` odziedziczono po braku odpowiedzi. Patrz `prd.md` §Open Questions poz. 6. — Właściciel: użytkownik. Blokuje: nic.
9. ~~**Czy wiele kluczy w jednym repozytorium i rotacja klucza są poza zakresem?**~~ Rozstrzygnięte — oba są wymienione w `zalozenia.md` §Zakres MVP / poza zakresem jako **poza zakresem v0.1** („Wiele niezależnych kluczy w jednym repo (`--key-name`)" oraz „Rotacja klucza i wycofywanie dostępu odbiorcy z przepisaniem historii"). Format pliku jest na oba gotowy przez `key_id`. — Właściciel: użytkownik. Blokuje: nic.
10. **Czy pozostałe wymagania dostaną własne historyjki użytkownika?** — **odłożone świadomie 2026-08-06: nie dostaną.** Luka w zapisie, nie w pokryciu — kryteria akceptacji żyją jako scenariusze i są bogatsze niż byłyby historyjki. Patrz `prd.md` §Open Questions poz. 8. — Właściciel: użytkownik. Blokuje: nic.

## Parked

- **Zarządzanie odbiorcami i praca zespołowa** — **przeniesione 2026-08-11 do `S-09`**, więc nie leży już tutaj. Powodem zaparkowania było PRD §Non-Goals, i ten zapis zostaje w mocy **dla v0.1**; `S-09` stoi poza nią.
- **Kompatybilność z repozytoriami oryginalnego git-crypt** — Dlaczego: PRD §Non-Goals; własny format bez ścieżki migracji.
- **Ukrywanie metadanych** — Dlaczego: PRD §Non-Goals; nazwy plików, rozmiary i fakt zmiany pozostają jawne z założenia konstrukcji.
- **Ochrona przed skompromitowaną maszyną** — Dlaczego: PRD §Non-Goals; po odblokowaniu sekrety leżą jawnie na dysku.
- **Buforowanie dyskowe dla wielkich plików** — Dlaczego: odłożone świadomie 2026-08-06 (`zalozenia.md` §Otwarte decyzje poz. 5). Dziś każdy plik trafia do RAM w całości i **szczyt pamięci wynosi ~2× jego rozmiar** — zmierzone: 128 MB → 258 MB RSS. Odłożenie nic nie zamraża: obie drogi wyjścia (buforowanie na dysku, nowy `suite` z trybem blokowym) mieszczą się w zamrożonym formacie, więc powrót do tematu nie kosztuje więcej później niż dziś. Wraca przy pierwszym zgłoszeniu OOM albo przy decyzji o wspieraniu plików rzędu gigabajta; produkt celuje dziś w pliki konfiguracyjne rzędu kilobajtów.
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
- **S-07: pobrać gotową binarkę dla swojej platformy** — Wydane 2026-08-07, tag `v0.1.0`, przebieg `31211254819`; element bez folderu zmiany, więc bez archiwizacji. Pięć targetów, dziesięć artefaktów, atestacja proweniencji na każdym archiwum. Lekcja: „pipeline nigdy nie uruchomiony" bywa nieprawdą, którą utrwala sama dokumentacja — `roadmap.md` twierdziła, że krok atestacji czeka na pierwszy tag, podczas gdy `workflow_dispatch` wykonał go już 2026-08-05. Druga: próba dowodzi tylko tego, co naprawdę wykonuje — wejście `tag` było `required` i nieczytane, więc dry run nazywał archiwa od gałęzi i nie ćwiczył nazewnictwa, na którym stoi wydanie.

Po zamknięciu `S-06` całość przeszła przez przegląd końcowy w trzech rundach. Raporty nie są już wersjonowane — ich treść odtwarza `git show <sha>` z commitów, które je wprowadziły:

- **runda 1, warstwa kryptograficzna i format** (`40a15b1`) — wyciek klucza głównego przez `git-xcrypt diff` na wyeksportowanym pliku z komentarzami, dwa testy `required = true`, które same sobie ustawiały tę flagę, i zamrożony format pliku klucza bez ani jednego wektora.
- **runda 2, integracja z gitem** (`53240f2`) — osiem znalezisk, w tym `required =` z pustą wartością czytane przez gita jako `false`, `export-key` piszący do sąsiedniego checkoutu i skan historii pomijający refy innych worktree.
- **runda 3, kompletność i jakość** (`775705c`) — scenariusz akceptacyjny jako jeden test z prawdziwym `push`, testy właściwości na `proptest`, CI na trzech platformach, `deny.toml`, metadane publikacyjne, zmierzony MSRV 1.88 oraz dwie mutacje przechodzące zielono, zamknięte testami.

Cztery decyzje właściciela wynikłe z tych rund wykonano w `87736eb`, `7fb6707`, `eae1049` i `33d3081`; ich zapis powstał w `20e0cc7`.
