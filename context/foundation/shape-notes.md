---
project: "git-crypt"
context_type: greenfield
created: 2026-08-03
updated: 2026-08-03
checkpoint:
  current_phase: 8
  phases_completed: [1, 2, 3, 4, 5, 6, 7]
  gray_areas_resolved:
    - topic: "context type"
      decision: "greenfield — istniejące cargo new to pusty szkielet, nie system do zachowania"
    - topic: "kategoria bólu"
      decision: "tarcie w przepływie pracy + dane uwięzione poza repo + brakująca funkcja w istniejących narzędziach"
    - topic: "zakres głównej persony"
      decision: "pojedynczy deweloper — autor, własne repozytoria"
    - topic: "koszt status quo"
      decision: "sekrety trzymane poza repo + ręczne kopiowanie plików między maszynami"
    - topic: "wgląd odróżniający od status quo"
      decision: "samowystarczalna binarka bez zależności od systemowego gpg"
    - topic: "moment wyzwalający"
      decision: "klon repo na nowej maszynie; zmiana sekretu wymagająca ręcznej synchronizacji; zakładanie nowego projektu"
    - topic: "transport klucza"
      decision: "plik klucza — export/import; jeden ręczny transfer na maszynę"
    - topic: "model wieloosobowy"
      decision: "poza MVP — płaski model jednoosobowy; brak add-user/list-users w v1"
    - topic: "zakres pierwszej wersji"
      decision: "pełny przepływ 1-6 w v1; użytkownik świadomie wybrał dłuższy harmonogram zamiast cięcia zakresu"
  frs_drafted: 11
  quality_check_status: accepted
product_type: cli
target_scale:
  users: small
  qps: n/a
  data_volume: small
timeline_budget:
  mvp_weeks: 6
  hard_deadline: null
  after_hours_only: true
---

# Pomysł początkowy

Źródło: `context/foundation/zalozenia.md` (przekazany jako argument `/10x-shape`).

## Vision & Problem Statement

Pojedynczy deweloper trzyma sekrety swoich projektów poza repozytorium i kopiuje je ręcznie między maszynami. Ból uderza w trzech momentach: przy klonowaniu repo na nowej maszynie (kod jest, sekretów nie ma), przy zmianie sekretu, która wymaga ręcznej synchronizacji na pozostałe maszyny, oraz przy zakładaniu każdego nowego projektu. Ból ma trzy składowe: tarcie w przepływie pracy, dane uwięzione poza repozytorium (konfiguracja nie jest wersjonowana razem z kodem) oraz brakująca funkcja w istniejących narzędziach.

Wgląd: samowystarczalna binarka bez zależności od systemowego `gpg`. Zależność od zewnętrznego `gpg` jest punktem tarcia, którego istniejące narzędzia nie usuwają.

## User & Persona

Główna persona: **pojedynczy deweloper — autor projektu**, zarządzający sekretami we własnych repozytoriach na wielu maszynach.

- Kontekst: własne projekty, brak współdzielenia repozytorium z innymi osobami jako scenariusz podstawowy.
- Moment sięgnięcia po produkt: klon repo na nowej maszynie, zmiana sekretu wymagająca propagacji, zakładanie nowego projektu.

## Access Control

Pojedynczy użytkownik, model płaski. Brak ról i brak rozróżnienia uprawnień: kto posiada klucz repozytorium, ten odszyfrowuje wszystko; kto go nie ma, widzi wyłącznie ciphertext.

Klucz trafia na kolejną maszynę przez **plik klucza**: `export-key` zapisuje go do pliku, użytkownik przenosi plik na nową maszynę wybranym przez siebie kanałem, `unlock` go wczytuje. Jest to jeden ręczny transfer na maszynę — produkt rozwiązuje synchronizację sekretów, ale nie transport samego klucza.

Zarządzanie odbiorcami (`add-user` / `list-users`, koperty kluczy per odbiorca) jest **poza MVP** — patrz `## Non-Goals`.

## Success Criteria

### Primary

Pełny przepływ przechodzi od początku do końca:

1. `git init` + `git-crypt init` w nowym repozytorium.
2. Wpisanie wzorców (`sekrety/`, `*.env`) do `.git-crypt`.
3. Commit i push pliku zawierającego sekret.
4. Bloby w zdalnym repozytorium są zaszyfrowane; `.git-crypt` pozostaje jawny.
5. Klon na drugiej maszynie → `export-key` / `unlock` → treść identyczna z oryginałem.
6. `git status` po `unlock` jest czysty.

### Secondary

- Generator `.git-crypt` → `.gitattributes` działa — konfiguracja w składni `.gitignore` zamiast ręcznej edycji `.gitattributes`.

### Guardrails

- Filtr nigdy nie uszkadza pliku użytkownika — żadnej cichej utraty ani zniekształcenia treści przy clean/smudge; błąd przerywa operację gita zamiast przepuszczać uszkodzone dane.
- Klucz nigdy nie trafia do repozytorium — ani do drzewa roboczego, ani do commita, ani na `stdout` poza jawnym `export-key`.
- Determinizm — niezmieniony plik nigdy nie pokazuje się jako zmodyfikowany po `unlock`.

## Timeline acknowledgment

Potwierdzono dnia 2026-08-03: 6-tygodniowy MVP wymaga stałego zaangażowania; użytkownik zaakceptował.

## Functional Requirements

Wszystkie FR mają priorytet `must-have` — użytkownik nie wskazał żadnego jako `nice-to-have`, co jest spójne z wyborem pełnego przepływu 1-6 i 6-tygodniowego harmonogramu. Lista została potwierdzona jako kompletna.

### Inicjacja i konfiguracja

- FR-001: Użytkownik może zainicjować szyfrowanie w repozytorium jedną komendą, która generuje klucz i rejestruje filtry gita. Priorytet: must-have
  > Socrates: Kontrargument przyjęty — "ponowne `init` na skonfigurowanym repozytorium może nadpisać klucz; błąd w detekcji stanu to utrata dostępu do własnych danych". FR zostaje; kontrargument staje się wiążącym ograniczeniem: wykrywanie stanu istniejącego jest częścią FR-001, nie detalem implementacji.
- FR-002: Użytkownik może wskazać pliki i katalogi do szyfrowania w pliku konfiguracyjnym o składni `.gitignore`. Priorytet: must-have
  > Socrates: Kontrargument przyjęty — "dwa źródła prawdy, które się rozjadą: git czyta wyłącznie `.gitattributes`, więc edycja jednego pliku bez synchronizacji daje ciche nieszyfrowanie". FR zostaje; sposób niedopuszczenia do rozjazdu jest otwarty — patrz `## Open Questions`.
- FR-003: Użytkownik może zsynchronizować `.gitattributes` z pliku konfiguracyjnego. Priorytet: must-have
  > Socrates: Brak kontrargumentu; zostaje bez zmian.

### Szyfrowanie

- FR-004: Użytkownik może commitować plik pasujący do wzorca i otrzymać w repozytorium wyłącznie jego zaszyfrowaną postać. Priorytet: must-have
  > Socrates: Brak kontrargumentu; zostaje bez zmian. To rdzeń produktu.
- FR-005: Użytkownik może pracować na odszyfrowanej treści w katalogu roboczym bez żadnych dodatkowych komend. Priorytet: must-have
  > Socrates: Brak kontrargumentu; zostaje bez zmian.
- FR-006: Użytkownik może oglądać różnice na odszyfrowanej treści. Priorytet: must-have
  > Socrates: Brak kontrargumentu; zostaje bez zmian.

### Klucz

- FR-007: Użytkownik może wyeksportować klucz repozytorium do pliku. Priorytet: must-have
  > Socrates: Kontrargument przyjęty — "komenda, która wydaje klucz, to najkrótsza droga do wycieku: wystarczy raz uruchomić ją w CI albo z przekierowaniem do katalogu repozytorium". FR zostaje; kontrargument wzmacnia guardrail "klucz nigdy nie trafia do repozytorium".
- FR-008: Użytkownik może odblokować sklonowane repozytorium plikiem klucza. Priorytet: must-have
  > Socrates: Kontrargument przyjęty — "utrata pliku klucza to utrata wszystkich sekretów; jeden plik bez kopii zapasowej jest pojedynczym punktem awarii dla całej historii repozytorium". FR zostaje; kwestia kopii zapasowej klucza jest nierozstrzygnięta — patrz `## Open Questions`.
- FR-009: Użytkownik może zablokować repozytorium z powrotem. Priorytet: must-have
  > Socrates: Kontrargument przyjęty — "`lock` kasuje klucz z `.git/`; użytkownik bez wcześniejszego `export-key` traci dostęp do własnych danych jedną komendą". FR zostaje; zabezpieczenie przed tym scenariuszem jest nierozstrzygnięte — patrz `## Open Questions`.

### Widoczność i dystrybucja

- FR-010: Użytkownik może sprawdzić, które pliki są szyfrowane, a które powinny być, a nie są. Priorytet: must-have
  > Socrates: Kontrargument przyjęty — "płytkie sprawdzenie daje fałszywe poczucie bezpieczeństwa: rzetelna odpowiedź wymaga przeszukania całej historii, nie tylko HEAD". FR zostaje; głębokość sprawdzenia jest nierozstrzygnięta — patrz `## Open Questions`.
- FR-011: Użytkownik może zainstalować gotową binarkę dla swojej platformy bez kompilowania i bez dodatkowych bibliotek. Priorytet: must-have
  > Socrates: Kontrargument przyjęty — "binarka narzędzia kryptograficznego bez podpisu i odtwarzalnego builda to nowy wektor zaufania; `cargo install` ma przynajmniej łańcuch od źródła". FR zostaje; kontrargument obciąża sposób wydawania binariów, nie samą możliwość.

## User Stories

### US-01: Odzyskanie sekretów po klonie na nowej maszynie

- **Given** repozytorium z zaszyfrowanymi sekretami w zdalnym hostingu oraz plik klucza przeniesiony na nową maszynę
- **When** użytkownik klonuje repozytorium i uruchamia `unlock` wskazując plik klucza
- **Then** pliki objęte wzorcami są w katalogu roboczym w postaci jawnej, identycznej z oryginałem, a `git status` nie pokazuje żadnych zmian

#### Acceptance Criteria

- Bez pliku klucza klon pokazuje wyłącznie ciphertext, a komenda kończy się czytelnym błędem, nie panic.
- Po `unlock` treść każdego odszyfrowanego pliku jest bajt w bajt równa treści sprzed commita.
- `git status` bezpośrednio po `unlock` jest czysty.

## Business Logic

Aplikacja rozstrzyga na podstawie wzorców ścieżek, które pliki opuszczają maszynę wyłącznie w postaci zaszyfrowanej, i gwarantuje, że ta sama treść zawsze daje ten sam ciphertext.

Reguła konsumuje dwa wejścia użytkownika: deklarację wzorców (jakie ścieżki są tajne) oraz treść plików w katalogu roboczym. Jej wyjściem jest rozstrzygnięcie per plik — jawny albo zaszyfrowany — plus sam ciphertext, powtarzalny dla tej samej treści.

Determinizm nie jest tu detalem technicznym, lecz częścią reguły domenowej: bez niego niezmieniony plik pokazywałby się jako zmodyfikowany przy każdym sprawdzeniu stanu, a produkt byłby bezużyteczny w codziennej pracy niezależnie od poprawności szyfrowania.

Użytkownik napotyka regułę biernie — nie wywołuje jej, tylko obserwuje jej skutek: w katalogu roboczym widzi treść jawną, w zdalnym repozytorium tę samą treść zaszyfrowaną.

## Non-Functional Requirements

- Codzienne operacje gita (dodanie do indeksu, commit, checkout, przełączenie gałęzi) na typowym pliku konfiguracyjnym nie są odczuwalnie wolniejsze niż w repozytorium bez szyfrowania. Próg liczbowy nierozstrzygnięty — patrz `## Open Questions`.
- Poza nazwą pliku, przybliżonym rozmiarem i faktem wystąpienia zmiany żadna treść objęta wzorcem nie jest odczytywalna bez klucza.
- Repozytorium zaszyfrowane na jednej z trzech wspieranych platform odszyfrowuje się bez różnic na dwóch pozostałych, włącznie z zachowaniem końców linii.

## Non-Goals

Nie-cele funkcjonalne:

- **Zarządzanie odbiorcami i praca zespołowa** — brak `add-user` / `list-users`, kopert kluczy i wsparcia dla wielu osób. Źródło: rozstrzygnięcie z Fazy 2 (płaski model jednoosobowy).
- **Kompatybilność z repozytoriami oryginalnego git-crypt** — własny format; repozytorium zaszyfrowane przez AGWA/git-crypt nie jest obsługiwane i nie ma ścieżki migracji. Źródło: rozstrzygnięcie zapisane w `zalozenia.md`.

Nie-cele niefunkcjonalne:

- **Ukrywanie metadanych** — nazwy plików, ścieżki, rozmiary i fakt zmiany pozostają jawne. Świadomie akceptowane ograniczenie konstrukcji.
- **Ochrona przed skompromitowaną maszyną** — po `unlock` sekrety leżą jawnie na dysku; atakujący z dostępem do konta użytkownika jest poza modelem zagrożeń.

## Quality cross-check

Bramka przeszła w komplecie (2026-08-03): Access Control, Business Logic, artefakty projektu, potwierdzenie kosztu czasowego i Non-Goals są obecne; „zachowane zachowanie" nie dotyczy sesji greenfield.

Brak luk bramkowych. Nierozstrzygnięte kwestie zebrane niżej — cztery z nich (pozycje 1-4) wyszły z rundy Sokratesa i dotykają bezpieczeństwa; pozycja 1 jest oznaczona jako blokująca.

## Open Questions

1. **Jak nie dopuścić do rozjazdu `.git-crypt` i `.gitattributes`?** — git czyta wyłącznie `.gitattributes`; edycja jednego pliku bez synchronizacji daje ciche nieszyfrowanie. Kontrargument przyjęty przy FR-002, rozwiązanie nierozstrzygnięte. Owner: użytkownik. Blokuje: tak (dotyka rdzenia bezpieczeństwa).
2. **Co chroni użytkownika przed utratą jedynego pliku klucza?** — kontrargument przyjęty przy FR-008; brak kopii zapasowej klucza oznacza utratę całej historii sekretów. Owner: użytkownik.
3. **Co chroni przed `lock` wykonanym bez wcześniejszego `export-key`?** — kontrargument przyjęty przy FR-009; jedna komenda może odciąć dostęp do własnych danych. Owner: użytkownik.
4. **Jak głęboko `status` sprawdza repozytorium — HEAD czy cała historia?** — kontrargument przyjęty przy FR-010; płytkie sprawdzenie daje fałszywe poczucie bezpieczeństwa, głębokie może być zbyt wolne. Owner: użytkownik.
5. **Jaki jest liczbowy próg dla NFR wydajnościowego?** — „bez odczuwalnego spowolnienia" nie jest mierzalne. Owner: użytkownik.
6. **Czy któreś FR ma być `nice-to-have`?** — pytanie o priorytety zostało bez odpowiedzi; przyjęto domyślne `must-have` dla wszystkich 11. Owner: użytkownik.
7. **Czy wiele kluczy w jednym repo i rotacja klucza są nie-celami?** — pytanie o nie-cele funkcjonalne zostało częściowo bez odpowiedzi; obie pozycje pozostają nierozstrzygnięte zamiast być zapisane jako wykluczone. Owner: użytkownik.

## Forward: tech-stack

Treść wybiegająca w przyszłość, przechwycona z `zalozenia.md`. **Nie jest częścią PRD** — trafia do kroku wyboru/oceny stosu po `/10x-prd`.

- Język: Rust, edycja 2024; MSRV utrzymywany w CI. Struktura `lib` + cienki `bin`.
- Kryptografia: rekomendacja AES-256-SIV (RFC 5297, crate `aes-siv`) jako deterministyczny AEAD; alternatywa XChaCha20-Poly1305 z nonce liczonym z plaintextu. Wyłącznie audytowane biblioteki, zero `unsafe` we własnym kodzie.
- Format pliku: własny magic, wersja formatu w nagłówku od pierwszego wydania.
- Integracja: filtry `clean` / `smudge` / `diff` w `.git/config`, aktywowane wpisami w `.gitattributes`.
- Dystrybucja: `cargo install`; binaria z GitHub Actions dla Windows, macOS (x86_64 + aarch64) i Linux (preferowany target `musl`); instalacja standardowymi narzędziami platform (brew).
- Odbiorcy (poza MVP, gdyby wróciło): natywnie w Rust — rekomendacja formatu `age` zamiast zewnętrznego `gpg`.
- Nierozstrzygnięte kwestie stosu: licencja projektu wobec GPL-3.0 projektów inspirujących, nazwa crate'a i binarki wobec kolizji z oryginalnym `git-crypt`.
