---
project: "git-xcrypt"
version: 1
status: draft
created: 2026-08-03
context_type: greenfield
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

## Vision & Problem Statement

Pojedynczy deweloper trzyma sekrety swoich projektów poza repozytorium i kopiuje je ręcznie między maszynami. Ból uderza w trzech momentach: przy klonowaniu repozytorium na nowej maszynie (kod jest, sekretów nie ma), przy zmianie sekretu, która wymaga ręcznej synchronizacji na pozostałe maszyny, oraz przy zakładaniu każdego nowego projektu. Ból ma trzy składowe: tarcie w przepływie pracy, dane uwięzione poza repozytorium (konfiguracja nie jest wersjonowana razem z kodem) oraz brakująca funkcja w istniejących narzędziach.

Wgląd: samowystarczalna binarka bez zależności od systemowego `gpg`. Zależność od zewnętrznego `gpg` jest punktem tarcia, którego istniejące narzędzia nie usuwają.

## User & Persona

Główna persona: **pojedynczy deweloper — autor projektu**, zarządzający sekretami we własnych repozytoriach na wielu maszynach.

- Kontekst: własne projekty, brak współdzielenia repozytorium z innymi osobami jako scenariusz podstawowy.
- Moment sięgnięcia po produkt: klon repozytorium na nowej maszynie, zmiana sekretu wymagająca propagacji, zakładanie nowego projektu.

## Success Criteria

### Primary

Pełny przepływ przechodzi od początku do końca:

1. `git init` + `git-xcrypt init` w nowym repozytorium.
2. Wpisanie wzorców (`sekrety/`, `*.env`) do `.git-xcrypt`.
3. Commit i push pliku zawierającego sekret.
4. Bloby w zdalnym repozytorium są zaszyfrowane; `.git-xcrypt` pozostaje jawny.
5. Klon na drugiej maszynie → `export-key` / `unlock` → treść identyczna z oryginałem.
6. `git status` po `unlock` jest czysty.

### Secondary

- Generator `.git-xcrypt` → `.gitattributes` działa — konfiguracja w składni `.gitignore` zamiast ręcznej edycji `.gitattributes`.

### Guardrails

- Filtr nigdy nie uszkadza pliku użytkownika — żadnej cichej utraty ani zniekształcenia treści; błąd przerywa operację gita zamiast przepuszczać uszkodzone dane.
- Klucz nigdy nie trafia do repozytorium — ani do drzewa roboczego, ani do commita, ani na `stdout` poza jawnym `export-key`.
- Determinizm — niezmieniony plik nigdy nie pokazuje się jako zmodyfikowany po `unlock`.

## User Stories

### US-01: Odzyskanie sekretów po klonie na nowej maszynie

- **Given** repozytorium z zaszyfrowanymi sekretami w zdalnym hostingu oraz plik klucza przeniesiony na nową maszynę
- **When** użytkownik klonuje repozytorium i uruchamia `unlock` wskazując plik klucza
- **Then** pliki objęte wzorcami są w katalogu roboczym w postaci jawnej, identycznej z oryginałem, a `git status` nie pokazuje żadnych zmian

#### Acceptance Criteria

- Bez pliku klucza klon pokazuje wyłącznie ciphertext, a komenda kończy się czytelnym błędem, nie panic.
- Po `unlock` treść każdego odszyfrowanego pliku jest bajt w bajt równa treści sprzed commita.
- `git status` bezpośrednio po `unlock` jest czysty.

# TODO: historyjki użytkownika dla FR-002, FR-007, FR-009, FR-010 — see Open Questions

## Functional Requirements

Wszystkie FR mają priorytet `must-have` — użytkownik nie wskazał żadnego jako `nice-to-have`, co jest spójne z wyborem pełnego przepływu 1-6 i 6-tygodniowego harmonogramu. Lista została potwierdzona jako kompletna.

### Inicjacja i konfiguracja

- FR-001: Użytkownik może zainicjować szyfrowanie w repozytorium jedną komendą, która generuje klucz i rejestruje filtry gita. Priorytet: must-have
  > Socratic: Kontrargument przyjęty — "ponowne `init` na skonfigurowanym repozytorium może nadpisać klucz; błąd w detekcji stanu to utrata dostępu do własnych danych". FR zostaje; kontrargument staje się wiążącym ograniczeniem: wykrywanie stanu istniejącego jest częścią FR-001, nie detalem implementacji.
- FR-002: Użytkownik może wskazać pliki i katalogi do szyfrowania w pliku konfiguracyjnym o składni `.gitignore`. Priorytet: must-have
  > Socratic: Kontrargument przyjęty — "dwa źródła prawdy, które się rozjadą: git czyta wyłącznie `.gitattributes`, więc edycja jednego pliku bez synchronizacji daje ciche nieszyfrowanie". FR zostaje; sposób niedopuszczenia do rozjazdu jest otwarty — patrz `## Open Questions`.
- FR-003: Użytkownik może zsynchronizować `.gitattributes` z pliku konfiguracyjnego. Priorytet: must-have
  > Socratic: Brak kontrargumentu; zostaje bez zmian.

### Szyfrowanie

- FR-004: Użytkownik może commitować plik pasujący do wzorca i otrzymać w repozytorium wyłącznie jego zaszyfrowaną postać. Priorytet: must-have
  > Socratic: Brak kontrargumentu; zostaje bez zmian. To rdzeń produktu.
- FR-005: Użytkownik może pracować na odszyfrowanej treści w katalogu roboczym bez żadnych dodatkowych komend. Priorytet: must-have
  > Socratic: Brak kontrargumentu; zostaje bez zmian.
- FR-006: Użytkownik może oglądać różnice na odszyfrowanej treści. Priorytet: must-have
  > Socratic: Brak kontrargumentu; zostaje bez zmian.

### Klucz

- FR-007: Użytkownik może wyeksportować klucz repozytorium do pliku. Priorytet: must-have
  > Socratic: Kontrargument przyjęty — "komenda, która wydaje klucz, to najkrótsza droga do wycieku: wystarczy raz uruchomić ją w CI albo z przekierowaniem do katalogu repozytorium". FR zostaje; kontrargument wzmacnia guardrail "klucz nigdy nie trafia do repozytorium".
- FR-008: Użytkownik może odblokować sklonowane repozytorium plikiem klucza. Priorytet: must-have
  > Socratic: Kontrargument przyjęty — "utrata pliku klucza to utrata wszystkich sekretów; jeden plik bez kopii zapasowej jest pojedynczym punktem awarii dla całej historii repozytorium". FR zostaje; kwestia kopii zapasowej klucza jest nierozstrzygnięta — patrz `## Open Questions`.
- FR-009: Użytkownik może zablokować repozytorium z powrotem. Priorytet: must-have
  > Socratic: Kontrargument przyjęty — "`lock` kasuje klucz z `.git/`; użytkownik bez wcześniejszego `export-key` traci dostęp do własnych danych jedną komendą". FR zostaje; zabezpieczenie przed tym scenariuszem jest nierozstrzygnięte — patrz `## Open Questions`.

### Widoczność i dystrybucja

- FR-010: Użytkownik może sprawdzić, które pliki są szyfrowane, a które powinny być, a nie są. Priorytet: must-have
  > Socratic: Kontrargument przyjęty — "płytkie sprawdzenie daje fałszywe poczucie bezpieczeństwa: rzetelna odpowiedź wymaga przeszukania całej historii, nie tylko HEAD". FR zostaje; głębokość sprawdzenia jest nierozstrzygnięta — patrz `## Open Questions`.
- FR-011: Użytkownik może zainstalować gotową binarkę dla swojej platformy bez kompilowania i bez dodatkowych bibliotek. Priorytet: must-have
  > Socratic: Kontrargument przyjęty — "binarka narzędzia kryptograficznego bez podpisu i odtwarzalnego builda to nowy wektor zaufania; instalacja ze źródeł ma przynajmniej łańcuch od źródła". FR zostaje; kontrargument obciąża sposób wydawania binariów, nie samą możliwość.

## Non-Functional Requirements

- Codzienne operacje gita (dodanie do indeksu, commit, checkout, przełączenie gałęzi) na typowym pliku konfiguracyjnym nie są odczuwalnie wolniejsze niż w repozytorium bez szyfrowania. # TODO: próg liczbowy — see Open Questions
- Poza nazwą pliku, przybliżonym rozmiarem i faktem wystąpienia zmiany żadna treść objęta wzorcem nie jest odczytywalna bez klucza.
- Repozytorium zaszyfrowane na jednej z trzech wspieranych platform odszyfrowuje się bez różnic na dwóch pozostałych, włącznie z zachowaniem końców linii.

## Business Logic

Aplikacja rozstrzyga na podstawie wzorców ścieżek, które pliki opuszczają maszynę wyłącznie w postaci zaszyfrowanej, i gwarantuje, że ta sama treść zawsze daje ten sam ciphertext.

Reguła konsumuje dwa wejścia użytkownika: deklarację wzorców (jakie ścieżki są tajne) oraz treść plików w katalogu roboczym. Jej wyjściem jest rozstrzygnięcie per plik — jawny albo zaszyfrowany — plus sam ciphertext, powtarzalny dla tej samej treści.

Determinizm nie jest tu detalem technicznym, lecz częścią reguły domenowej: bez niego niezmieniony plik pokazywałby się jako zmodyfikowany przy każdym sprawdzeniu stanu, a produkt byłby bezużyteczny w codziennej pracy niezależnie od poprawności szyfrowania.

Użytkownik napotyka regułę biernie — nie wywołuje jej, tylko obserwuje jej skutek: w katalogu roboczym widzi treść jawną, w zdalnym repozytorium tę samą treść zaszyfrowaną.

## Access Control

Pojedynczy użytkownik, model płaski. Brak ról i brak rozróżnienia uprawnień: kto posiada klucz repozytorium, ten odszyfrowuje wszystko; kto go nie ma, widzi wyłącznie ciphertext.

Klucz trafia na kolejną maszynę przez **plik klucza**: `export-key` zapisuje go do pliku, użytkownik przenosi plik na nową maszynę wybranym przez siebie kanałem, `unlock` go wczytuje. Jest to jeden ręczny transfer na maszynę — produkt rozwiązuje synchronizację sekretów, ale nie transport samego klucza.

Zarządzanie odbiorcami (`add-user` / `list-users`, koperty kluczy per odbiorca) jest poza zakresem MVP — patrz `## Non-Goals`.

## Non-Goals

Nie-cele funkcjonalne:

- **Zarządzanie odbiorcami i praca zespołowa** — brak `add-user` / `list-users`, kopert kluczy i wsparcia dla wielu osób. Źródło: rozstrzygnięcie z fazy kształtowania (płaski model jednoosobowy).
- **Kompatybilność z repozytoriami oryginalnego git-crypt** — własny format; repozytorium zaszyfrowane przez projekt bazowy nie jest obsługiwane i nie ma ścieżki migracji.

Nie-cele niefunkcjonalne:

- **Ukrywanie metadanych** — nazwy plików, ścieżki, rozmiary i fakt zmiany pozostają jawne. Świadomie akceptowane ograniczenie konstrukcji.
- **Ochrona przed skompromitowaną maszyną** — po `unlock` sekrety leżą jawnie na dysku; atakujący z dostępem do konta użytkownika jest poza modelem zagrożeń.

## Open Questions

1. ~~**Jak nie dopuścić do rozjazdu `.git-xcrypt` i `.gitattributes`?**~~ **Rozstrzygnięte 2026-08-04 — rozjazd zostaje usunięty z konstrukcji, a nie pilnowany procedurą.** `.gitattributes` dostaje jedną statyczną linię `* filter=git-xcrypt`, która nie zależy od treści `.git-xcrypt`, więc nie ma jak się z nią rozjechać; filtr jest wywoływany dla każdego pliku i sam decyduje, czytając `.git-xcrypt` jako jedyne źródło prawdy. Warunek wykonalności zmierzony: filtr musi być długożyjący (`filter.git-xcrypt.process`) — proces na plik daje 22× spowolnienie, filtr długożyjący +10%. Odrzucone: hak `pre-commit` (obchodzony przez `--no-verify`, a treść i tak jest utrwalana już przy `git add`). Cena: promień rażenia błędu filtra rośnie na wszystkie pliki repozytorium, stąd obowiązkowy test `passthrough(x) == x`. Pełne pomiary i konsekwencje: `zalozenia.md` §Integracja z git → „Konstrukcja catch-all". Owner: użytkownik. Blokuje: nic.
2. **Co chroni użytkownika przed utratą jedynego pliku klucza?** — kontrargument przyjęty przy FR-008; brak kopii zapasowej klucza oznacza utratę całej historii sekretów. Owner: użytkownik.
3. ~~**Co chroni przed `lock` wykonanym bez wcześniejszego `export-key`?**~~ **Rozstrzygnięte 2026-08-04.** `lock` jest domyślnie interaktywny i wymaga wpisania `yes`; flaga `--yes` daje tryb nieinteraktywny, ale ostrzeżenie pojawia się w obu (w nieinteraktywnym na `stderr`). Ostrzeżenie podaje `key_id`, **nie klucz** — wypisywanie klucza rozważono i odrzucono, bo zostawiałby ślad w scrollbacku, w logu CI i w drzewie roboczym przy przekierowaniu; komunikat kieruje do `export-key`. Osobno: `lock` odmawia, gdy pliki objęte wzorcem mają niezacommitowane zmiany, i `--yes` tego nie obchodzi. Szczegóły: `zalozenia.md` §Zarządzanie kluczami → „Zabezpieczenia `lock`". Owner: użytkownik. Blokuje: nic.
4. ~~**Jak głęboko `status` sprawdza repozytorium — HEAD czy cała historia?**~~ **Rozstrzygnięte 2026-08-04: cała osiągalna historia.** Przesłanka „głębokie może być zbyt wolne" okazała się słaba — skan nie wymaga deszyfrowania, wystarczy 11 bajtów magic na blob o pasującej ścieżce, więc koszt zależy od liczby obiektów, nie od ich rozmiaru. `status` dostaje trzy zadania: kompletność konfiguracji, skan historii i `--fix` naprawiający to, co da się naprawić bezpiecznie (ponowne dodanie plików leżących jawnie w `HEAD`/indeksie, bez przepisywania historii). Kod wyjścia `5` przy znalezisku, do użycia jako bramka CI. Czyszczenie historii zostaje poza v0.1 — `status` raportuje ekspozycję i wypisuje procedurę, w której **rotacja sekretu wyprzedza przepisanie historii**, bo przepisanie czyści repozytorium, ale nie cofa wycieku. Szczegóły: `zalozenia.md` §Zakres MVP. Owner: użytkownik. Blokuje: nic.
5. **Jaki jest liczbowy próg dla NFR wydajnościowego?** — „bez odczuwalnego spowolnienia" nie jest mierzalne. Owner: użytkownik.
6. **Czy któreś FR ma być `nice-to-have`?** — pytanie o priorytety pozostało bez odpowiedzi podczas kształtowania; przyjęto domyślne `must-have` dla wszystkich 11. Owner: użytkownik.
7. **Czy wiele kluczy w jednym repozytorium i rotacja klucza są nie-celami?** — pytanie o nie-cele funkcjonalne pozostało częściowo bez odpowiedzi; obie pozycje są nierozstrzygnięte zamiast zapisane jako wykluczone. Owner: użytkownik.
8. **Historyjki użytkownika dla pozostałych FR** — przechwycono wyłącznie US-01 (główna ścieżka). FR-002, FR-007, FR-009 i FR-010 mają nieoczywiste kryteria akceptacji i zasługują na własne Given/When/Then. Owner: użytkownik.
