---
project: "git-xcrypt"
version: 1
status: draft
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
| S-01  | transparent-encrypt-decrypt  | commitować plik i dostać ciphertext w repo, plaintext w katalogu roboczym | F-01          | FR-001, FR-004, FR-005 | proposed |
| S-02  | gitignore-style-config       | wskazać pliki do szyfrowania w składni `.gitignore`                      | S-01          | FR-002, FR-003         | blocked  |
| S-03  | key-export-and-unlock        | odzyskać sekrety po klonie na drugiej maszynie                           | S-01          | US-01, FR-007, FR-008  | proposed |
| S-04  | lock-repository              | zamknąć odblokowane repozytorium z powrotem                              | S-03          | FR-009                 | blocked  |
| S-05  | decrypted-diff               | oglądać różnice na treści jawnej                                         | S-01          | FR-006                 | proposed |
| S-06  | encryption-status-check      | sprawdzić, co jest szyfrowane, a co powinno być                          | S-02          | FR-010                 | blocked  |
| S-07  | cross-platform-binaries      | pobrać gotową binarkę dla swojej platformy                               | S-01          | FR-011                 | blocked  |

## Streams

Pomoc nawigacyjna — grupuje elementy dzielące łańcuch wymagań wstępnych. Kanoniczna kolejność jest w grafie zależności niżej.

| Stream | Temat                    | Łańcuch                              | Uwaga                                                                        |
| ------ | ------------------------ | ------------------------------------ | ---------------------------------------------------------------------------- |
| A      | Rdzeń szyfrowania        | `F-01` → `S-01` → `S-03` → `S-04`    | Ścieżka gwiazdy przewodniej; niesie całe ryzyko techniczne celu `learn`.      |
| B      | Konfiguracja i widoczność | `S-02` → `S-06`                      | Dołącza do Strumienia A w `S-01`. Oba elementy zablokowane decyzjami.         |
| C      | Narzędzia pracy          | `S-05`                               | Dołącza do A w `S-01`. Jedyny element bez własnej niewiadomej.                |
| D      | Dystrybucja              | `S-07`                               | Dołącza do A w `S-01`. Blokowany decyzjami o nazwie i licencji, nie techniką. |

## Baseline

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
- **PRD refs:** FR-001, FR-004, FR-005, §Business Logic, §Non-Functional Requirements (metadane)
- **Prerequisites:** F-01
- **Parallel with:** —
- **Blockers:** —
- **Unknowns:**
  - Który szyfr i jaki układ nagłówka formatu? `zalozenia.md` rekomenduje AES-256-SIV z wersją formatu w nagłówku — Właściciel: użytkownik. Blokuje: nie.
  - Jak `init` wykrywa, że repozytorium jest już skonfigurowane, żeby nie nadpisać klucza? — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** tu zapada format pliku — po tym elemencie każda zmiana formatu psuje istniejące repozytoria, dlatego wersja formatu musi trafić do nagłówka już w pierwszym commicie. Kryptografia świadomie nie jest osobnym fundamentem: ląduje w pierwszym elemencie, który jej faktycznie potrzebuje, żeby nie budować warstwy przed jej użyciem.
- **Status:** proposed

### S-02: Konfiguracja w składni .gitignore

- **Outcome:** użytkownik wskazuje pliki i katalogi do szyfrowania we własnym pliku konfiguracyjnym o składni `.gitignore` i synchronizuje z niego konfigurację czytaną przez gita.
- **Change ID:** gitignore-style-config
- **PRD refs:** FR-002, FR-003, §Success Criteria → Secondary
- **Prerequisites:** S-01
- **Parallel with:** S-03, S-05, S-07
- **Blockers:** —
- **Unknowns:**
  - Jak nie dopuścić do rozjazdu pliku konfiguracyjnego i konfiguracji czytanej przez gita? — Właściciel: użytkownik. Blokuje: tak.
  - Jak przetłumaczyć wzorzec katalogowy `katalog/` i negacje na semantykę, którą git faktycznie honoruje? — Właściciel: użytkownik. Blokuje: nie.
  - Jakie zachowanie domyślne przy braku deklaracji EOL — binarny czy `text=auto`? Rozstrzygnięte, że `.git-xcrypt` przejmuje semantykę `text`/`-text`/`eol=lf`/`eol=crlf`, bo `-text` odbiera te atrybuty na plikach szyfrowanych; otwarte zostaje samo domyślne. Patrz `zalozenia.md` §Końce linii. — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** rozjazd konfiguracji daje ciche nieszyfrowanie — sekret wygląda na chroniony, a trafia do repozytorium jawnie. To najgroźniejszy tryb awarii w całym produkcie i dlatego element nie nadaje się do planowania przed zapadnięciem decyzji.
- **Status:** blocked

### S-03: Przeniesienie repozytorium na drugą maszynę

- **Outcome:** użytkownik eksportuje klucz repozytorium do pliku, a po klonie na innej maszynie odblokowuje repozytorium tym plikiem i dostaje treść bajt w bajt identyczną z oryginałem.
- **Change ID:** key-export-and-unlock
- **PRD refs:** US-01, FR-007, FR-008
- **Prerequisites:** S-01
- **Parallel with:** S-02, S-05, S-07
- **Blockers:** —
- **Unknowns:**
  - Co chroni użytkownika przed utratą jedynego pliku klucza? — Właściciel: użytkownik. Blokuje: nie.
- **Risk:** komenda wydająca klucz to najkrótsza droga do wycieku — ścieżka zapisu musi wykluczać katalog repozytorium i standardowe wyjście. Element realizuje jedyną historyjkę użytkownika w PRD, więc jego niepowodzenie oznacza, że produkt nie rozwiązuje pierwotnego bólu.
- **Status:** proposed

### S-04: Zamknięcie repozytorium

- **Outcome:** użytkownik zamyka odblokowane repozytorium jedną komendą i pliki objęte wzorcami wracają w katalogu roboczym do postaci zaszyfrowanej.
- **Change ID:** lock-repository
- **PRD refs:** FR-009
- **Prerequisites:** S-03
- **Parallel with:** —
- **Blockers:** —
- **Unknowns:**
  - Co chroni przed zamknięciem repozytorium bez wcześniejszego wyeksportowania klucza? — Właściciel: użytkownik. Blokuje: tak.
- **Risk:** jedna komenda może odciąć użytkownika od całej historii własnych sekretów. Rzadko używana ścieżka o wysokim koszcie błędu jest jednocześnie tą najsłabiej przetestowaną w praktyce.
- **Status:** blocked

### S-05: Różnice na treści odszyfrowanej

- **Outcome:** użytkownik ogląda różnice między wersjami pliku na treści jawnej zamiast na szumie ciphertextu.
- **Change ID:** decrypted-diff
- **PRD refs:** FR-006
- **Prerequisites:** S-01
- **Parallel with:** S-02, S-03, S-07
- **Blockers:** —
- **Unknowns:** —
- **Risk:** to trzecia ścieżka deszyfrowania obok szyfrowania przy commicie i odszyfrowywania przy checkoucie — musi dzielić kod z pozostałymi, inaczej rozjedzie się z formatem przy pierwszej jego zmianie. Jedyny element bez własnej niewiadomej, więc dobry kandydat na pracę równoległą, gdy reszta czeka na decyzje.
- **Status:** proposed

### S-06: Widoczność stanu szyfrowania

- **Outcome:** użytkownik sprawdza jedną komendą, które pliki są szyfrowane i które pasują do wzorca, a mimo to trafiły do repozytorium jawnie.
- **Change ID:** encryption-status-check
- **PRD refs:** FR-010
- **Prerequisites:** S-02
- **Parallel with:** —
- **Blockers:** —
- **Unknowns:**
  - Jak głęboko sprawdzać repozytorium — tylko bieżący stan czy całą historię? — Właściciel: użytkownik. Blokuje: tak.
- **Risk:** płytkie sprawdzenie daje fałszywe poczucie bezpieczeństwa i jest gorsze niż brak komendy; głębokie może być na tyle wolne, że nikt go nie uruchamia. Element odpowiada na największe realne ryzyko produktu — sekret zacommitowany przed konfiguracją — więc kompromis między głębokością a czasem jest jego istotą, nie detalem.
- **Status:** blocked

### S-07: Gotowa binarka dla trzech platform

- **Outcome:** użytkownik pobiera plik wykonywalny dla Windows, macOS lub Linuksa i używa go bez kompilowania i bez instalowania dodatkowych bibliotek.
- **Change ID:** cross-platform-binaries
- **PRD refs:** FR-011, §Non-Functional Requirements (identyczne zachowanie na trzech platformach)
- **Prerequisites:** S-01
- **Parallel with:** S-02, S-03, S-05
- **Blockers:** —
- **Unknowns:**
  - ~~Jaka nazwa crate'a i binarki wobec kolizji z oryginalnym `git-crypt` w menedżerach pakietów?~~ Rozstrzygnięte 2026-08-04: `git-xcrypt`. — Właściciel: użytkownik. Blokuje: nie.
  - Jaka licencja projektu wobec GPL-3.0 projektów inspirujących? — Właściciel: użytkownik. Blokuje: tak.
- **Risk:** publikacja pod kolidującą nazwą albo bez rozstrzygniętej licencji jest trudna do wycofania — obie decyzje muszą zapaść przed pierwszym publicznym wydaniem, nie po nim. Sama technika jest tu najprostsza w całej roadmapie; blokują decyzje, nie kod.
- **Status:** blocked

## Backlog Handoff

| Roadmap ID | Change ID                    | Sugerowany tytuł zadania                            | Gotowe do `/10x-plan` | Uwagi                                       |
| ---------- | ---------------------------- | --------------------------------------------------- | --------------------- | ------------------------------------------- |
| F-01       | git-integration-test-harness | Harness testów na prawdziwym repozytorium git       | tak                   | Uruchom `/10x-plan git-integration-test-harness` |
| S-01       | transparent-encrypt-decrypt  | Przezroczyste szyfrowanie w jednym repozytorium     | nie                   | Czeka na F-01                               |
| S-02       | gitignore-style-config       | Konfiguracja w składni .gitignore                   | nie                   | Zablokowane: rozjazd konfiguracji           |
| S-03       | key-export-and-unlock        | Eksport klucza i odblokowanie po klonie             | nie                   | Czeka na S-01                               |
| S-04       | lock-repository              | Zamknięcie repozytorium                             | nie                   | Zablokowane: zabezpieczenie przed utratą klucza |
| S-05       | decrypted-diff               | Różnice na treści odszyfrowanej                     | nie                   | Czeka na S-01                               |
| S-06       | encryption-status-check      | Widoczność stanu szyfrowania                        | nie                   | Zablokowane: głębokość sprawdzenia          |
| S-07       | cross-platform-binaries      | Binarki dla Windows, macOS i Linuksa                | nie                   | Zablokowane: nazwa i licencja               |

## Open Roadmap Questions

1. **Jak nie dopuścić do rozjazdu pliku konfiguracyjnego i konfiguracji czytanej przez gita?** — Właściciel: użytkownik. Blokuje: `S-02` (a przez zależność również `S-06`).
2. **Co chroni przed zamknięciem repozytorium bez wcześniejszego wyeksportowania klucza?** — Właściciel: użytkownik. Blokuje: `S-04`.
3. **Jak głęboko `status` sprawdza repozytorium — bieżący stan czy cała historia?** — Właściciel: użytkownik. Blokuje: `S-06`.
4. ~~**Jaka nazwa crate'a i binarki wobec kolizji z oryginalnym `git-crypt`?**~~ Rozstrzygnięte 2026-08-04: `git-xcrypt` dla crate'a i binarki. — Właściciel: użytkownik. Blokuje: nic.
5. **Jaka licencja projektu wobec GPL-3.0 projektów inspirujących?** — Właściciel: użytkownik. Blokuje: `S-07`.
6. **Co chroni użytkownika przed utratą jedynego pliku klucza?** — Właściciel: użytkownik. Blokuje: nic; wpływa na zakres `S-03`.
7. **Jaki jest liczbowy próg dla wymagania wydajnościowego?** — Właściciel: użytkownik. Blokuje: roadmap-wide; bez liczby nie da się stwierdzić, czy wymaganie zostało spełnione.
8. **Czy któreś wymaganie ma być opcjonalne zamiast koniecznego?** — Właściciel: użytkownik. Blokuje: roadmap-wide; wszystkie 11 wymagań przyjęto jako konieczne domyślnie, bez potwierdzenia.
9. **Czy wiele kluczy w jednym repozytorium i rotacja klucza są poza zakresem?** — Właściciel: użytkownik. Blokuje: roadmap-wide; nierozstrzygnięte, więc nie trafiły ani do elementów, ani do `Parked`.
10. **Czy pozostałe wymagania dostaną własne historyjki użytkownika?** — Właściciel: użytkownik. Blokuje: nic; wpływa na jakość kryteriów akceptacji w `S-02`, `S-03`, `S-04`, `S-06`.

## Parked

- **Zarządzanie odbiorcami i praca zespołowa** — Dlaczego: PRD §Non-Goals; model jest jednoosobowy, klucz przenoszony plikiem.
- **Kompatybilność z repozytoriami oryginalnego git-crypt** — Dlaczego: PRD §Non-Goals; własny format bez ścieżki migracji.
- **Ukrywanie metadanych** — Dlaczego: PRD §Non-Goals; nazwy plików, rozmiary i fakt zmiany pozostają jawne z założenia konstrukcji.
- **Ochrona przed skompromitowaną maszyną** — Dlaczego: PRD §Non-Goals; po odblokowaniu sekrety leżą jawnie na dysku.

## Done

- **F-01: (foundation) weryfikować zachowanie na prawdziwym repozytorium git** — Zarchiwizowano 2026-08-04 → `context/archive/2026-08-04-git-integration-test-harness/`. Lekcja: —.
