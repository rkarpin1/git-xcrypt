# Read `.gitattributes` from the path's ancestors — Implementation Plan

## Overview

`AttributeResolver` (`src/git/attributes.rs`) buduje dziś stos atrybutów gita,
przechodząc **całe drzewo robocze** w poszukiwaniu `.gitattributes`
(`collect_attribute_files`, `attributes.rs:942`, wołane z `::new`,
`attributes.rs:1450`). Git czyta te pliki wyłącznie z katalogów **na ścieżce**
pytanego pliku, więc wszystko poza przodkami jest dla wyniku bezczynne — a
kosztuje `read_dir` na katalog i `file_type()` na każdy wpis. Zmierzone
(przegląd 2026-08-06): drzewo z 5281 katalogami / 480 000 plików ignorowanych →
`git add` jednego zadeklarowanego pliku **220 ms zamiast 10 ms**; `git-xcrypt
status` 210 ms; koszt liniowy w liczbie wpisów katalogowych. To jedyna
zmierzona pozycja w produkcie skalująca się z liczbą plików **nieśledzonych**.

Zmieniamy resolver tak, żeby sondował `.gitattributes` wyłącznie na łańcuchu
przodków faktycznie pytanych ścieżek, a nowo odkryty plik wywoływał **pełną
przebudowę** `Search` dokładnie dzisiejszym kodem konstrukcji — zero nowej
logiki precedencji. Nota `status` o obcych liniach `filter` zachowuje pełne
przejście po drzewie (decyzja właściciela, 2026-08-07). Czwarty budżet
wydajnościowy w `tests/performance.rs` pilnuje, żeby spacer nie wrócił.

## Current State Analysis

- **`collect_attribute_files` (`attributes.rs:942`)** — iteracyjny spacer po
  całym drzewie: sonduje `<dir>/.gitattributes` po nazwie
  (`symlink_metadata().is_file()`, dowiązania wykluczone), pomija `.git`
  i katalogi-dowiązania, wchodzi do każdego pozostałego katalogu. Jedyny
  wołający: `AttributeResolver::new`.
- **Precedencja w `::new` (`attributes.rs:1430–1523`)** — jedno sortowanie
  (płycej → głębiej, `attributes.rs:1466`; `Search` dopasowuje
  last-added-first, więc plik bliższy ścieżce wygrywa), makra `[attr]` tylko
  dla pliku w korzeniu (`is_root`, `attributes.rs:1472`), `info/attributes`
  dodawane **ostatnie** (`attributes.rs:1498`), plik globalny przez
  `new_globals` na początku. Kopie indeksowe (`staged_fallbacks`,
  `attributes.rs:1003`) wchodzą do tej samej listy i tego samego sortowania.
- **Dwóch konsumentów**: `filter.rs:308` (`attribute_stack`, leniwie raz na
  proces — ścieżka gorąca: odmowa konwersji przed szyfrowaniem i diagnoza po
  porażce tagu) oraz `status.rs:1052` (rozstrzyganie osi `filter` i `text`/`eol`
  dla każdej zadeklarowanej ścieżki w indeksie).
- **`sources()` (`attributes.rs:1603`)** zasila w `status`
  `foreign_source_note` (`status.rs:1401–1432`) — nota istnieje po to, żeby
  nazwać plik atrybutów sięgający ścieżek **jeszcze nieśledzonych**, czyli
  taki, którego leniwy resolver może nigdy nie odwiedzić.
- **Ryzyko nazwane przez przegląd**: resolver stoi pod odmową ścieżki `clean`
  przy `required = true` — błąd w precedencji daje albo fałszywą odmowę
  blokującą całe repozytorium, albo przeoczoną linię `text`, czyli plik nie do
  odzyskania przy checkoucie.
- **Warianty przycięcia odrzucone w przeglądzie 2026-08-06, nie wracamy**: po
  `.gitignore` (git czyta atrybuty z katalogów ignorowanych — przycięcie
  kosztuje plik), po indeksie (świeży nieśledzony `secrets/` z własnym
  `.gitattributes` wypada z widoku), po zagnieżdżonym `.git` (nie dotyka
  przypadku `target/`).
- **Nieaktualna notatka kosztowa**: `zalozenia.md` („stos atrybutów budowany
  leniwie… 135 ms → 137 ms" oraz „Koszt, zmierzony… 18 ms → 22 ms") mierzyła
  czyste drzewa plików śledzonych; koszt poddrzew nieśledzonych nie był nigdzie
  przyjęty świadomie.

## Desired End State

`AttributeResolver::new` nie wykonuje żadnego przejścia po drzewie.
`resolve(path)` sonduje `.gitattributes` w katalogach-przodkach `path`
(korzeń → katalog pliku), każdy katalog najwyżej raz na proces; odkrycie
nowego pliku atrybutów przebudowuje `Search` w całości dzisiejszym kodem.
Odpowiedzi `resolve` są bajt w bajt identyczne z dotychczasowymi — dowiedzione
scenariuszem parytetu z żywym `git check-attr` i strażnikiem kolejności
odkrywania. `git add` zadeklarowanego pliku w drzewie z katalogiem budowania
wraca do rzędu 10 ms; nota `status` niezmieniona co do treści i pokrycia;
czwarty budżet w `performance.rs` czerwieni powrót pełnego spaceru.

### Key Discoveries:

- Wzorce z `<dir>/.gitattributes` są ograniczone do poddrzewa `<dir>` (gix
  dostaje `root = work_tree` i ścieżkę źródła), więc kolejność **między
  rozłącznymi gałęziami** nie wpływa na wynik — znaczenie ma wyłącznie porządek
  wewnątrz łańcucha przodków i pozycja `info`/globala. Pełna przebudowa
  istniejącym kodem konstrukcji czyni oba pytania bezprzedmiotowymi.
- Sonda per plik zostaje identyczna (`symlink_metadata().is_file()`,
  dowiązanie-plik wykluczone). Znika natomiast wykluczenie
  katalogów-dowiązań — dawny spacer nie wchodził w katalog będący dowiązaniem,
  sonda stat-uje przez ścieżkę tak, jak robi to sam git przy otwieraniu
  `<dir>/.gitattributes`. Ścieżki, o które pyta git, nie prowadzą przez
  dowiązania katalogowe (zawartość pod dowiązaniem nie jest śledzona jako
  ścieżki pod nim), więc różnica jest teoretyczna — i w kierunku gita.
- `staged_fallbacks` zostają wczytywane w całości przy konstrukcji jak dziś
  (indeks już przeczytany, lista mała, wzorce ograniczone do swoich
  katalogów) — przy przebudowie wchodzą do wspólnego sortowania jak dotąd.
- `smudge` stosu nie buduje (`git checkout` zmierzony 10 ms → 10 ms) — ta
  ścieżka nie wymaga zmian ani pomiaru.
- `foreign_lines_touching` czyta źródło z dysku, więc na ścieżkach kopii
  indeksowych (plik nieobecny) i tak odpowiada błędem i nota je pomija — lista
  dla noty to w praktyce: pliki na dysku + `info/attributes` + plik globalny.

## What We Are NOT Doing

- Żadnego przycinania po `.gitignore`, indeksie ani zagnieżdżonym `.git` —
  odrzucone z powodami w przeglądzie 2026-08-06.
- Żadnej adopcji `gix-worktree::Stack` — nowa zależność i przepisanie wnętrza
  resolvera; odrzucone na rzecz przebudowy istniejącym kodem.
- Żadnego przyrostowego dokładania do `gix_attributes::Search` — poprawność
  wisiałaby na nieudokumentowanej semantyce kolejności list.
- Nota `status` **nie** zmienia treści ani pokrycia — status dalej enumeruje
  całe drzewo dla tej jednej rzeczy.
- Bez zmian w `smudge`, `sync`, `lock`, `unlock` i w czymkolwiek, co dotyka
  bajtów na dysku — format, `looks_binary` i rendering `.gitattributes`
  nietknięte.
- Bez optymalizacji dwóch `F_FULLFSYNC` w `lock`/`unlock` (osobna otwarta
  pozycja przeglądu, nierozstrzygnięta świadomie).

## Implementation Approach

Leniwość wchodzi wyłącznie w **odkrywanie źródeł**; składanie precedencji
zostaje dosłownie dzisiejsze. `AttributeResolver` dostaje: zbiór katalogów już
wysondowanych, listę odkrytych plików na dysku i zachowaną listę kopii
indeksowych. `resolve(path)` najpierw domyka sondowanie łańcucha przodków;
jeśli przybył nowy plik — przebudowuje `Search` od zera funkcją wyjętą
z dzisiejszego `::new` (globals → posortowane źródła drzewa → `info` na
końcu). Liczba przebudów jest ograniczona liczbą plików atrybutów na
odpytanych łańcuchach (typowo 0–2), nie liczbą katalogów. `status` dostaje dla
noty osobną, jawną enumerację pełnego drzewa — dokładnie tę listę, którą dziś
zwraca `sources()`.

## Phase 1: Lazy resolver with rebuild-on-discovery

### Overview

Cała zmiana mechanizmu plus dowód, że nic się nie rozjechało: parytet z żywym
gitem i strażnik kolejności odkrywania, zmutowany w obie strony.

### Changes Required:

#### 1. Lazy discovery in the resolver

**File**: `src/git/attributes.rs`

**Purpose**: `::new` przestaje wołać spacer po drzewie; `resolve` sonduje
przodków i przebudowuje `Search` przy odkryciu. Zachowanie `resolve` co do
odpowiedzi — identyczne.

**Contract**: Sygnatury publiczne bez zmian: `AttributeResolver::new(work_tree,
common_dir, global, ignore_case, staged)` i `resolve(&mut self, relative_path:
&[u8]) -> Resolution`. Wewnątrz:

- konstrukcja buduje `Search` z tego, co znane bez spaceru (globals, wszystkie
  `staged`, `info/attributes` na końcu — istniejący tor);
- `resolve` wyprowadza z `relative_path` (bajty, separator `/`) łańcuch
  katalogów: korzeń, potem każdy kolejny prefiks do katalogu pliku; każdy
  katalog spoza zbioru wysondowanych dostaje jedną sondę
  `symlink_metadata(<dir>/.gitattributes).is_file()` i wpis do zbioru;
- odkrycie nowego pliku → przebudowa: jedna prywatna funkcja składająca
  `Search` z (global, posortowane [pliki na dysku + staged], info) — wyjęta
  z dzisiejszego `::new` tak, żeby konstrukcja i przebudowa były **tym samym
  kodem**; sortowanie i `is_root` bez zmian;
- klucz zbioru wysondowanych: bajty względnej ścieżki katalogu jak podana —
  przy `core.ignorecase` druga pisownia tego samego katalogu kosztuje najwyżej
  drugą sondę, którą system plików i tak rozstrzyga tak samo (to jest
  dokładnie semantyka „probe by name" z komentarza nad dzisiejszym
  spacerem, który należy zaktualizować, nie skasować).

#### 2. `sources()` documents its narrowed meaning

**File**: `src/git/attributes.rs`

**Purpose**: `sources()` zwraca odtąd źródła **konsultowane** (odkryte na
łańcuchach + staged + info + global), nie wszystkie w drzewie. Komentarz
dokumentu tę granicę i wskazuje enumerację pełną jako właściwe narzędzie dla
pytań o całe drzewo.

**Contract**: sygnatura bez zmian; jedyny zewnętrzny konsument (`status`)
przechodzi na enumerację pełną (pkt 3), więc nikt nie czyta już `sources()`
jako „wszystko w drzewie".

#### 3. Full-tree enumeration for the status note

**File**: `src/git/attributes.rs`, `src/commands/status.rs`

**Purpose**: nota o obcych liniach `filter` musi dalej widzieć każdy plik
atrybutów w drzewie — także w katalogu bez śledzonych ścieżek, bo dokładnie
przed takim ostrzega.

**Contract**: nowa publiczna funkcja w `attributes.rs` (np.
`pub fn attribute_files_under(work_tree: &Path) -> Vec<PathBuf>`) opakowująca
dotychczasowy spacer (`collect_attribute_files` zostaje jako jej wnętrze —
nie kasujemy przetestowanego kodu, przestaje go tylko wołać resolver).
`foreign_source_note` w `status.rs:1401` buduje listę: wynik enumeracji +
`info/attributes` + plik globalny — czyli dokładnie zbiór, po którym dziś
iteruje przez `sources()` i który daje niepuste odpowiedzi
`foreign_lines_touching` (kopie indeksowe i dziś odpadają na odczycie
z dysku). Treść noty: bajt w bajt bez zmian.

#### 4. Parity scenario and the discovery-order guard

**File**: `src/git/attributes.rs` (testy modułu), `tests/attributes.rs`

**Purpose**: dowód, że leniwe odkrywanie odpowiada tym, czym odpowiadał spacer
— także w jedynym wymiarze, który tylko leniwość może zepsuć: kolejności
odkrywania łańcuchów.

**Contract**:

- **Strażnik kolejności** (testy modułu, wzorem istniejących testów pytających
  żywy `git check-attr`): drzewo z `.gitattributes` w korzeniu, `a/`, `a/b/`
  oraz `info/attributes` i plikiem globalnym; te same ścieżki rozstrzygane
  w kilku permutacjach kolejności (najgłębsza najpierw; najpłytsza najpierw;
  rodzeństwo `a/c/` między nimi) muszą dać identyczne `Resolution` między sobą
  i z odpowiedzią `git check-attr` na osiach `filter`, `text`, `eol`. Wariant
  z `core.ignorecase` w obu wartościach.
- **Mutacje, obie strony, wykonane naprawdę**: (a) usunięcie sortowania
  w funkcji przebudowy → czerwono; (b) sonda, która nie odkrywa plików poniżej
  korzenia → czerwono. Po weryfikacji mutacje wycofane.
- **Scenariusz w `tests/attributes.rs`**: istniejące scenariusze (m.in.
  `a_linked_worktrees_own_config_is_the_one_that_counts`, staged-fallback,
  fold ASCII) przechodzą bez zmiany treści — one już jeżdżą po nowym torze,
  bo używają resolvera przez binarkę. Dodatkowo jedno rozszerzenie: repo,
  w którym plik atrybutów w **nieśledzonym** katalogu dalej pojawia się
  w nocie `status` (pokrycie pkt 3 — dokładnie przypadek, który leniwe
  `sources()` by zgubiło).

### Success Criteria:

#### Automated Verification:

- Pełny zestaw zielony: `cargo test --all-targets --locked --no-fail-fast`
- Lint i format: `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo fmt --all --check`
- Strażnik kolejności odkrywania zielony, a obie mutacje ((a) bez sortowania,
  (b) bez sondy poniżej korzenia) zweryfikowane na czerwono i wycofane
- Nota `status` o pliku atrybutów w nieśledzonym katalogu: scenariusz zielony,
  mutacja (nota z `sources()` zamiast enumeracji) czerwona

#### Manual Verification:

- Na tym repozytorium: `git add`, `git status`, `git-xcrypt status` zachowują
  się bez zmian (sanity, nie pomiar — pomiar jest w fazie 2)

**Implementation note**: Po ukończeniu tej fazy i zielonych weryfikacjach
automatycznych zatrzymaj się na ręczne potwierdzenie człowieka przed fazą 2.

---

## Phase 2: Fourth performance budget and the record of the decision

### Overview

Pomiar przed/po tym samym przyrządem, którym zmierzono problem; budżet
w `performance.rs` jako strażnik; zapis w `prd.md` i `zalozenia.md`.

### Changes Required:

#### 1. Before/after measurement on the synthetic tree

**Purpose**: liczby źródłowe dla progu i dla dokumentacji — odtworzenie
pomiaru z przeglądu 2026-08-06.

**Contract**: skrypt tymczasowy (scratchpad, nie repozytorium) buduje drzewo
rzędu kilku tysięcy katalogów z dziesiątkami tysięcy plików w katalogu
ignorowanym + jeden zadeklarowany plik; mierzone minimum z ≥5 przebiegów,
build `--release`: `git add <zadeklarowany>` i `git-xcrypt status`, na
binarce sprzed i po fazie 1. Oczekiwanie: `git add` z ~220 ms (skala z
raportu) do rzędu 10 ms; `git-xcrypt status` bez poprawy (pełne przejście dla
noty zostaje — to jest oczekiwany wynik, nie regresja).

#### 2. Fourth `#[ignore]` case in the performance suite

**File**: `tests/performance.rs`

**Purpose**: powrót pełnego spaceru w resolverze ma czerwienić test, tak jak
trzy istniejące budżety czerwienią swoje regresje.

**Contract**: przypadek w konwencji pliku (`#[ignore]`, `--release`, minimum
z 5 przebiegów, wypisuje zmierzone wartości): zbudowane na dysku drzewo
z ~3000 katalogów i kilkudziesięcioma tysiącami wpisów **poza** łańcuchem
zadeklarowanej ścieżki; mierzony czas `AttributeResolver::new` + pierwszego
`resolve` zadeklarowanej ścieżki. Budżet dobrany z zapasem 2–4× nad pomiarem
po zmianie (jak trzy istniejące), zapisany w teście z komentarzem nazywającym
pomiar źródłowy; musi leżeć wielokrotnie poniżej kosztu spaceru na tym samym
drzewie, żeby mutacja była jednoznaczna. Mutacja: przywrócenie spaceru
w `::new` → czerwono; wycofana po weryfikacji. Dwie zapisane pułapki
z nagłówka pliku (ściśliwość, zlib) tego przypadku nie dotyczą — dotyczy go
trzecia, którą należy dopisać: czas tworzenia drzewa testowego nie może
wchodzić do mierzonego okna.

#### 3. Record in the PRD and zalozenia

**File**: `context/foundation/prd.md` (§Non-Functional Requirements, §Open
Questions poz. 5 — dopisek), `context/foundation/zalozenia.md` (§Rozstrzyganie
atrybutów przez `status` → „Koszt, zmierzony"), `AGENTS.md` (§Testing, akapit
o `performance.rs` — liczba budżetów)

**Purpose**: czwarty budżet dołącza do trzech zamrożonych; nieprawdziwa już
notatka kosztowa zostaje sprostowana, w konwencji projektu (sprostowanie
z datą, nie ciche przepisanie).

**Contract**: `prd.md` §NFR dostaje czwartą pozycję z liczbą i metodą (minimum
z 5, `--release`, `#[ignore]`); `zalozenia.md` dostaje dopisek z datą przy
„Koszt, zmierzony": stary pomiar mierzył drzewo czyste, koszt poddrzew
nieśledzonych zmierzono 2026-08-06 (220 ms / 480 k plików), mechanizm od tej
zmiany sonduje przodków z przebudową przy odkryciu, nowy koszt = liczba
katalogów-przodków, nie wpisów drzewa; `AGENTS.md` aktualizuje zdanie o
„trzech liczbach" na cztery. `change.md` zmiany: `status: implemented` po
fazie 2 (archiwizacja przez `/10x-archive` osobno).

### Success Criteria:

#### Automated Verification:

- `cargo test --release --test performance -- --ignored --nocapture` —
  wszystkie cztery przypadki zielone, wypisane liczby zanotowane
- Mutacja (przywrócony spacer w `::new`) czerwieni nowy przypadek; wycofana
- Trzy dotychczasowe budżety bez pogorszenia (ten sam przebieg)
- Pełny zestaw, clippy, fmt — zielone

#### Manual Verification:

- Pomiar przed/po z pkt 1 wykonany i wpisany do `prd.md`/`zalozenia.md`
  (liczby, data, maszyna)
- `git add` zadeklarowanego pliku na drzewie syntetycznym w rzędzie 10 ms

---

## Testing Strategy

### Unit / module tests:

- Strażnik kolejności odkrywania (permutacje `resolve`) przeciw żywemu
  `git check-attr`, oba stany `core.ignorecase`
- Przebudowa = konstrukcja: ten sam tor kodu, więc bez osobnego testu
  równoważności — równoważność wymusza struktura

### Integration tests:

- Istniejące scenariusze `tests/attributes.rs` (worktree, staged fallback,
  fold, globalny plik atrybutów) — przechodzą bez zmian treści, jeżdżąc po
  nowym torze
- Rozszerzenie: nota `status` widzi plik atrybutów w nieśledzonym katalogu

### Manual testing steps:

1. Sanity na tym repozytorium po fazie 1 (`git add`, `git-xcrypt status`)
2. Pomiar syntetyczny przed/po w fazie 2, minimum z ≥5 przebiegów, `--release`
3. Odczyt wypisów nowego przypadku `performance.rs` — która strona budżetu

## Performance Considerations

Koszt po zmianie: jedna sonda `symlink_metadata` na katalog-przodka na proces
plus (rzadko) przebudowa `Search` parsująca znane pliki. Filtr długożyjący
płaci raz na operację gita; `status` płaci sondowanie łańcuchów zadeklarowanych
ścieżek plus — świadomie — pełne przejście dla noty. Repozytorium, które
niczego nie deklaruje, nie płaci nic (resolver nie powstaje — bez zmian).

## Migration Notes

Brak migracji: żaden bajt na dysku się nie zmienia, format nietknięty,
zachowanie `resolve` bajt w bajt zachowane. Jedyna widoczna różnica to czas.

## References

- Zmiana: `context/changes/attribute-stack-walks-ancestors/change.md`
- Pomiary i odrzucone warianty: `context/runs/2026-08-06-code-review-auto-fix.md`
  → „Otwarte — do decyzji właściciela" poz. 1 (niewersjonowane — katalog
  `context/runs/` jest w `.gitignore`)
- Kod: `src/git/attributes.rs:942` (`collect_attribute_files`),
  `src/git/attributes.rs:1430` (`AttributeResolver::new`),
  `src/commands/filter.rs:308` (`attribute_stack`),
  `src/commands/status.rs:1401` (`foreign_source_note`)

## Progress

> Konwencja: `- [ ]` oczekujące, `- [x]` wykonane. Dołącz ` — <commit sha>` po
> zakończeniu kroku. Nie zmieniaj tytułów kroków.

### Phase 1: Lazy resolver with rebuild-on-discovery

#### Automated

- [x] 1.1 Pełny zestaw zielony (`cargo test --all-targets --locked --no-fail-fast`) — 7843271
- [x] 1.2 Clippy i fmt zielone — 7843271
- [x] 1.3 Strażnik kolejności odkrywania zielony; mutacje (a) i (b) zweryfikowane na czerwono i wycofane — 7843271
- [x] 1.4 Scenariusz noty `status` dla nieśledzonego katalogu zielony; mutacja na `sources()` czerwona — 7843271

#### Manual

- [ ] 1.5 Sanity na tym repozytorium (`git add`, `git status`, `git-xcrypt status`)

### Phase 2: Fourth performance budget and the record of the decision

#### Automated

- [x] 2.1 Cztery przypadki `performance.rs` zielone w `--release`
- [x] 2.2 Mutacja (przywrócony spacer) czerwieni nowy przypadek; wycofana
- [x] 2.3 Pełny zestaw, clippy, fmt zielone

#### Manual

- [ ] 2.4 Pomiar przed/po wykonany i wpisany do `prd.md`/`zalozenia.md`
- [ ] 2.5 `git add` zadeklarowanego pliku na drzewie syntetycznym w rzędzie 10 ms
