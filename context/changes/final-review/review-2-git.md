# Final review, lens 2 of 3: git integration, portability, odd repository shapes

Data: 2026-08-04. Zakres: cały kod po S-01…S-06, obiektyw — protokół filtra
długożyjącego, zachowanie każdej komendy w nietypowych konfiguracjach
repozytorium, zapis do indeksu, końce linii wobec platform, kody wyjścia,
ścieżki, współbieżność. Przegląd 1 (kryptografia, format, klucz) przeczytany;
jego znaleziska nie są tu powtarzane.

Metoda: pomiar na prawdziwym gicie **2.55** w katalogach tymczasowych. Każde
podejrzenie najpierw próbowano obalić; wszystko poniżej przetrwało próbę i ma
test regresyjny **zweryfikowany jako czerwony na kodzie sprzed naprawy**.

Bramka po naprawach: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test` — czysto, **411 testów** (271 `lib` + 140 integracyjnych).

---

## Findings

Uporządkowane od najpoważniejszego.

### F1 — `filter.git-xcrypt.required = ` (pusta wartość) wyłącza zabezpieczenie, a `status` melduje, że wszystko gra

**Waga: wysoka.** Fail-open w bramce, która istnieje wyłącznie po to, żeby ten
stan wykryć.

**Gdzie:** `src/gitconfig.rs:95` (`get`) i `src/gitconfig.rs:121` (`is_true`).

**Zmierzone.** `gix-config` melduje dwa **różne** zapisy na dysku identycznie —
`raw_value` daje `Err(KeyMissing)` dla `key` (bez `=`) i `Ok("")` dla `key = ` —
a git tych dwóch **nie** utożsamia:

| na dysku | `git config --type=bool` | git przy checkoucie (`* text`) |
| --- | --- | --- |
| `autocrlf` (bez `=`) | `true` | CRLF |
| `autocrlf = ` (pusto) | **`false`** | **LF** |

`get` spłaszczał oba do `Some("")`, a `is_true("")` mówiło „prawda". Skutek na
prawdziwym gicie, cała ścieżka:

```
$ git config filter.git-xcrypt.required ""     # zapisuje `required = `
$ rm .git/git-xcrypt/keys/default              # filtr od teraz zawodzi
$ git add b.env
git-xcrypt: b.env: no repository key…
$ echo $?
0
$ git cat-file blob :b.env
B=2                                            # ← PLAINTEXT W BAZIE OBIEKTÓW
$ git-xcrypt status
VERDICT: no findings.
setup: git is configured to run the filter in this repository.
$ echo $?
0
```

Czyli dokładnie tryb awarii, przed którym broni twarda reguła `required = true`
— przy czym `status`, jedyne narzędzie zdolne go wykryć, potwierdzał zdrowie.
Drugą osią jest EOL: `core.autocrlf = ` dawało CRLF tam, gdzie git daje LF
(samonaprawialne, więc łagodniejsze).

**Naprawa.** `get` zwraca dla zapisu bez `=` **`Some("true")`** — czyli własne
odczytanie gita, w pisowni, o którą i tak pytają wszyscy wołający — a `is_true`
traci wariant `""`. Rozjazd przestaje być możliwy, bo obie strony mają teraz do
dyspozycji tę samą informację co git.

**Testy regresyjne** (oba czerwone na kodzie sprzed naprawy):
- `gitconfig::tests::an_empty_value_is_false_to_git_and_must_be_false_here`;
- `tests/status_command.rs::an_empty_required_value_is_reported_as_the_off_switch_git_reads_it_as`
  — pełna ścieżka przez prawdziwe repozytorium, bramka kończy się `5`.
- Poprawiony `eol::tests::every_git_spelling_of_true_means_crlf`: twierdził, że
  `core.autocrlf = ` jest prawdą „i musi być prawdą u nas". Zmierzone wyżej —
  nie jest.

---

### F2 — `export-key` zapisywał klucz do **innego checkoutu tego samego repozytorium**

**Waga: wysoka.** Naruszenie guardraila z PRD „klucz nigdy nie trafia do
repozytorium".

**Gdzie:** `src/commands/export_key.rs:68` — porównanie z **jednym** drzewem
roboczym, tym, z którego uruchomiono komendę.

**Zmierzone.** Podłączony worktree to inny katalog, więc nie jest prefiksem
tamtego i odmowa nie zapalała się w żadną stronę:

```
main$   git worktree add ../linked
main$   git-xcrypt export-key ../linked/stolen.key    → exit 0, plik zapisany
linked$ git status --porcelain                        → ?? stolen.key
linked$ git-xcrypt export-key ../main/stolen2.key     → exit 0, plik zapisany
main$   git status --porcelain                        → ?? stolen2.key
```

Klucz ląduje jako plik nieśledzony w checkoucie repozytorium, które sam otwiera —
jedno `git add -A` od commita. To ten sam scenariusz, który moduł nazywa
„najkrótszą drogą do wycieku w całym produkcie". Osobno, niżej wagą:
`git init --separate-git-dir` wynosi katalog gita poza drzewo, więc
`export-key <gitdir>/k.key` też przechodził.

**Naprawa.** Nowe `Repo::work_trees()` (`src/repo.rs:143`) wylicza **każdy**
checkout: ten, główny (przez `core.worktree`, jak `lock`) i każdy podłączony z
`worktrees/*/gitdir`. `export-key` odmawia dla każdego z nich, a dodatkowo dla
`git_dir` i `common_dir` — nic sensownego nie zapisuje wyeksportowanego klucza w
katalogu gita, a przy `--separate-git-dir` to jedyna rzecz, która go tam łapie.
`lock` znał tę geometrię od S-04; teraz obie komendy pytają tak samo.

**Testy regresyjne** (oba czerwone przed naprawą):
`a_destination_inside_another_checkout_of_the_same_repository_is_refused`
(obie strony: z głównego do podłączonego i odwrotnie),
`a_destination_inside_a_separate_git_directory_is_refused`.

---

### F3 — skan historii nie widział referencji innych worktree, więc realna ekspozycja kończyła się kodem `0`

**Waga: wysoka.** `status` istnieje po to, żeby odpowiedzieć na to jedno pytanie.

**Gdzie:** `src/history.rs:469` — otwierany był wyłącznie magazyn referencji tego
checkoutu.

**Zmierzone.** Commit, którego jedyną nazwą jest `.git/worktrees/wt/HEAD`, jest
dla gita osiągalny: przeżywa `git gc --prune=now`. Ten sam plaintext, ten sam
wzorzec, trzy stany:

| stan | `status` |
| --- | --- |
| commit wskazany gałęzią `side` | `5`, `1 path(s) leaked in history`, 3 commity |
| gałąź skasowana, zostaje `worktrees/wt/HEAD` | **`0`, `VERDICT: no findings`**, 2 commity |
| ten sam commit ponownie nazwany gałęzią | `5`, `1 path(s) leaked in history` |

Dokumentacja modułu obiecywała „każdy commit osiągalny z referencji, wraz z
`HEAD`", a `lock.rs` już wcześniej musiał chodzić po `common_dir/worktrees/` —
dwie komendy nie zgadzały się co do zawartości repozytorium.

**Naprawa.** `tips` rozbite na `collect_tips`, wołane raz dla tego checkoutu i
raz dla każdej rejestracji w `common_dir/worktrees/*` (przez
`Store::for_linked_worktree`, więc łapie też prywatne kategorie tamtych
worktree — `refs/bisect/*` w środku `git bisect`). Referencje wspólne wchodzą
raz, bo `tips` i tak jest `sort` + `dedup`.

**Test regresyjny:** `history::tests::a_secret_named_only_by_another_worktrees_head_is_found`,
zweryfikowany czerwony. Sprawdzone dodatkowo na binarce: `refs/bisect/bad` w
drugim worktree też jest teraz skanowane.

---

### F4 — plik atrybutów **poniżej korzenia** wyłączał filtr, a `status` twierdził, że repozytorium jest filtrowane

**Waga: średnia-wysoka.** Fałszywe „wszystko w porządku" dla repozytorium, w
którym `git add` zapisuje plaintext.

**Gdzie:** `src/commands/status.rs:577` — czytany był wyłącznie
`<worktree>/.gitattributes`.

**Zmierzone**, dwa warianty, oba w repozytorium ze skonfigurowanym filtrem i
zadeklarowanym `secrets/`:

```
secrets/.gitattributes  →  "* -filter"
.git/info/attributes    →  "secrets/** -filter"
```

W obu `git check-attr filter -- secrets/db.env` odpowiada `unset`, kolejny
`git add` zapisuje `hunter10` jawnie, a `status` drukuje
`setup: git is configured to run the filter in this repository` i kończy `0`, nie
wspominając o pliku ani słowem. Git rozstrzyga atrybuty z **każdego** katalogu na
ścieżce, potem z `$GIT_DIR/info/attributes`, potem z `core.attributesFile`, i
wygrywa **ostatnie** dopasowanie.

**Naprawa.** `gitattributes::foreign_filter_sources` przechodzi każdy
`.gitattributes` w drzewie roboczym (iteracyjnie, bez wchodzenia w `.git` i bez
podążania za dowiązaniami), następnie `info/attributes`, następnie
`core.attributesFile`, i zwraca pliki wraz z liniami dotykającymi `filter`.
`status` wypisuje je z nazwą pliku.

**Świadomie zostaje **notą**, nie luką (`5`).** Linia `*.psd filter=lfs` w
podkatalogu jest zupełnie zwyczajna; podniesienie tego do luki zapaliłoby bramkę
w każdym repozytorium z LFS. Rozstrzygnięcie, czy `status` ma **rozwiązywać**
atrybuty zamiast je nazywać, jest do decyzji człowieka — patrz niżej.

Koszt: `status` chodzi teraz po drzewie roboczym. Zmierzone na 10 003 plikach —
**63 ms** całości komendy.

**Testy regresyjne** (oba czerwone przed naprawą):
`an_attributes_file_below_the_root_that_turns_the_filter_off_is_named`,
`an_info_attributes_file_that_turns_the_filter_off_is_named` — obydwa najpierw
sprawdzają przez `git check-attr`, że fixture naprawdę zdejmuje filtr.

---

### F5 — `unlock` przerwany w połowie gubił cały raport, nie nazywał pliku i zostawiał `git status` brudny na zawsze

**Waga: średnia.** Utraty danych nie ma; jest niemożliwy do zdiagnozowania stan
pośredni.

**Gdzie:** `src/commands/unlock.rs:167,182,199` — trzy gołe `?` w pętli.

**Zmierzone**, na świeżym klonie z dwoma zadeklarowanymi plikami, gdzie drugi
leży w katalogu bez prawa zapisu (`chmod 555`):

```
$ git-xcrypt unlock ../k.key
git-xcrypt: i/o failure: Permission denied (os error 13)     ← nie nazywa pliku
$ echo $?
1
$ git status --porcelain
 M a/one.env       ← odszyfrowany, ale `forget_stat` nigdy nie pobiegł
```

Trzy osobne wady w jednym: raport ginie razem z listą tego, co już odszyfrowano;
odświeżenie cache'u `stat` nie następuje; komunikat nie nazywa pliku. Trzecia
najgorsza jest konsekwencja drugiej: **kolejny przebieg tego nie naprawi**, bo
plik jest już jawny, więc walk go nie wybiera i nigdy do niego nie wróci.
`lock` miał na to `interrupted()` od S-04; `unlock` nie.

**Naprawa.** Pętla zatrzymuje się na pierwszej porażce, ale nie wraca stamtąd:
`forget_stat` biegnie dla tego, co zdążyło się zapisać, a błąd dostaje nazwę
pliku (`named_io`) i podsumowanie (`interrupted`). Po naprawie:

```
git-xcrypt: i/o failure: z/two.env: could not replace it (Permission denied …)
unlock stopped part way: 1 file(s) are now in the clear and 1 are still encrypted.
The key is in place, so running unlock again picks up the rest once the cause
above is fixed.
$ git status --porcelain      ← czysto
```

**Test regresyjny:** `a_file_that_will_not_be_written_names_itself_and_reports_what_was_done`
(`#[cfg(unix)]`), zweryfikowany czerwony.

---

### F6 — plik o nazwie ≥ 224 bajtów uniemożliwiał `lock` i `unlock` na zawsze

**Waga: średnia.**

**Gdzie:** `src/atomic.rs:206` — nazwa pliku tymczasowego to nazwa celu plus
stałe 32 bajty (`.git-xcrypt-` + 16 hex + `.tmp`). Przy `NAME_MAX = 255` daje to
sufit 223 bajtów, którego git nie ma: plik o 224-bajtowej nazwie commituje się i
checkoutuje bez szemrania.

**Zmierzone.** `ENAMETOOLONG` nie jest `AlreadyExists`, więc leci przez
`atomic.rs:186` wprost na zewnątrz:

```
$ git-xcrypt lock --yes
git-xcrypt: i/o failure: secrets/zzz…zzz.env: File name too long (os error 63)
lock stopped part way: … The key has NOT been deleted, so running lock again
finishes the job.                       ← nieprawda: zawodzi identycznie zawsze
```

Repozytorium nie da się zamknąć, a sekret zostaje jawny w drzewie roboczym.
`unlock` łączyło to z F5 i było gorsze.

**Naprawa.** `temporary_name` skraca nazwę celu, gdy sufiks by się nie zmieścił
(`shorten`, bajtowo na Uniksie, przez formę tekstową gdzie indziej). Koszt
zapisany w dokumentacji funkcji: `strip_temporary_suffix` odtworzy wtedy nazwę
skróconą, więc residuum po zabitym przebiegu **na takim pliku** może nie zostać
rozpoznane jako należące do zadeklarowanej ścieżki i nie zostanie zamiecione.
To ten sam los, co residuum pod ścieżką niezadeklarowaną, i zastępuje komendę,
która nie działała w ogóle.

**Test regresyjny:** `atomic::tests::a_name_too_long_to_carry_the_suffix_is_still_written`
(200/223/224/255 bajtów, plus sprawdzenie, że nie zostaje residuum), czerwony
przed naprawą. Sprawdzone na binarce: `lock` i `unlock` przechodzą.

---

### F7 — zduplikowana sekcja zarządzana w `.gitattributes` przeżywała `sync`, a `sync --check` meldował „aktualne"

**Waga: średnia.**

**Gdzie:** `src/gitattributes.rs:331` — `upsert` przepisuje **pierwszy** region i
zostawia resztę.

**Zmierzone.** Plik o kształcie `BEGIN…END BEGIN…END`:

```
$ git-xcrypt sync --check ; echo $?
0                      ← "aktualne", przy dwóch sekcjach w pliku
$ git-xcrypt sync      ; cat .gitattributes
… obie sekcje nadal na miejscu
```

Niezbalansowane znaczniki były odrzucane, zbalansowany duplikat nie. Git bierze
**ostatnią** pasującą linię, więc rozstrzyga kopia, której nikt nie utrzymuje —
a nieaktualne `!text` na ścieżce, którą filtr nadal szyfruje, to dokładnie ta
korupcja CRLF, którą opisuje nagłówek modułu. Konflikt scalania na
`.gitattributes` rozwiązany „zostawmy obie strony" daje ten kształt naturalnie.

**Naprawa.** Drugi znacznik po zamknięciu pierwszej sekcji jest odrzucany, jak
niezbalansowany — z komunikatem mówiącym, że wygra kopia nieaktualna, i z
instrukcją.

**Test regresyjny:** `a_second_managed_section_is_refused_rather_than_left_to_win`,
czerwony przed naprawą.

---

### F8 — awaria wejścia/wyjścia na indeksie kasowała cały raport `status` i dawała kod `1`

**Waga: średnia.** Realna ekspozycja znikała za „narzędzie się zepsuło".

**Gdzie:** `src/commands/status.rs:733` i `:940` — dwa gołe `?`.

**Zmierzone.** `chmod 000 .git/index` w repozytorium z prawdziwym znaleziskiem w
historii: `git-xcrypt: i/o failure: Permission denied (os error 13)`, **kod 1**,
`stdout` pusty — bez werdyktu, bez sekcji `leaked`, bez nazwy pliku. To samo dla
`chmod a-w .git` i `status --fix` (porażka `Lock::acquire`). Moduł obsługuje
*analogiczne* porażki świadomie (`Listed::Unavailable` → `undetermined`, brak
klucza → `undetermined`, porażka `clean` → ostrzeżenie); ścieżka I/O je omijała.
`.git` zapisane przez `sudo git`, montowanie tylko do odczytu i ENOSPC na
`index.lock` dochodzą do tego stanu.

**Naprawa.** Oba wywołania mapują błąd na `Listed::Unavailable` /
`Restaged::Skipped`, czyli na tę samą odpowiedź, którą moduł już ma dla „nie dało
się odczytać indeksu". Raport wychodzi w całości, skan historii zostaje
dostarczony, a niemożność odczytu ląduje w `undetermined`.

**Test regresyjny:** `an_index_that_cannot_be_read_still_leaves_a_report_and_a_verdict`
(`#[cfg(unix)]`), czerwony przed naprawą: sprawdza kod `5`, obecność sekcji
`leaked in history` **i** wpisu `undetermined`.

---

### Poprawki dokumentacji, które były nieprawdziwymi twierdzeniami

Nie kod, ale komentarze twierdzące coś, czego kod nie robi — a to następny
przegląd wprowadza w błąd:

- `src/eol.rs:96` twierdziło, że `normalise_to_lf` jest idempotentne na
  **każdym** wejściu, jakie do niego dociera, bo lone CR jest klasyfikowany jako
  binarny. To prawda tylko dla `text=auto`; jawne `text` omija klasyfikator
  (`eol.rs:83`), więc `secrets/*.sh text` na treści z `\r\r\n` nie przeżywa
  round-tripu i `git status` pokazuje plik jako zmodyfikowany na stałe. Git robi
  dokładnie to samo przy jawnym `text` (o tym ostrzega `core.safecrlf`), więc to
  nie jest odstępstwo — ale zapisane jest teraz uczciwie, z odesłaniem do Otwartej
  decyzji 8.
- `src/history.rs:33` — lista „znanych granic" nie wymieniała **reflogu i
  pseudo-referencji**. Kanoniczne „ups": zacommitować sekret, `git reset --hard
  HEAD~1`, dopiero potem dopisać wzorzec → blob siedzi w bazie obiektów przez
  `gc.reflogExpire` (domyślnie 90 dni), a `status` melduje `no findings`.
  Granica jest sensowna (te obiekty są lokalne, żaden push ich nie niesie), ale
  nie była zapisana. Dopisana wraz z procedurą (`git reflog expire` + `git gc`) i
  z drugą granicą: żadna lokalna komenda nie mówi, co ma już zdalne.
- Tamże: pojedynczy zadeklarowany blob jest dekompresowany w całości, żeby
  ocenić 11 bajtów.

---

## Znaleziska świadomie odrzucone

- **Wstrzyknięcie linii do potwierdzenia `lock` przez nazwę pliku.**
  `lock.rs:151` drukuje kandydatów do zamiecenia dosłownie, więc plik o nazwie z
  `\n` renderuje się jako tekst narzędzia tuż nad nieodwracalnym pytaniem.
  Realne, ale wymaga prawa zapisu do drzewa roboczego użytkownika — a
  `zalozenia.md` §Bezpieczeństwo stawia „atakującego z dostępem do odszyfrowanego
  katalogu roboczego" **poza modelem zagrożeń**, i taki atakujący czyta klucz
  wprost. Do tego zamiatane jest wyłącznie residuum **nieśledzone**, więc
  sklonowane repozytorium tego nie dostarczy.
- **`lock` nie widzi zadeklarowanego pliku usuniętego z drzewa roboczego** i
  kończy `0`. Treść jest w indeksie jako blob, więc nic nie ginie.
- **`git -c core.autocrlf=…` jest niewidoczne dla filtra**, bo `gix-config` nie
  czyta `GIT_CONFIG_PARAMETERS` (czyta `GIT_CONFIG_COUNT/KEY_n/VALUE_n`).
  Determinizmu nie łamie — ścieżka `clean` konfiguracji nie czyta w ogóle — więc
  koszt to końce linii inne, niż prosiło `-c`, i następny `clean` i tak
  normalizuje z powrotem. Naprawa oznacza własny parser cudzysłowów gita;
  zapisane jako ograniczenie zależności.
- **`includeIf` w konfiguracji **globalnej** nie jest rozwijane** (`gix-config`
  `from_globals` podąża tylko za `include.path`). Ta sama waga i ten sam powód co
  wyżej; dotyczy wyłącznie `core.autocrlf`/`core.eol`.
- **`open_full(common_dir)` w podłączonym worktree czyta `config.worktree`
  głównego checkoutu**, a nie swojego. Dotyczy tylko `extensions.worktreeConfig`
  i tylko EOL; API `gix-config` skleja te dwie rzeczy, a wybór `common_dir` jest
  poprawny dla ważniejszej połowy (plik lokalny).
- **`GIT_DIR` + `GIT_WORK_TREE` bez `.git` w drzewie (wzorzec dotfiles)** — `init`
  odmawia z kodem `2` („not inside a git repository"), bo `gix-discover::upwards`
  chodzi po katalogach, a git eksportuje te zmienne również do procesu filtra
  (zmierzone). Cała konfiguracja jest nieobsługiwana i **fail-closed**; do
  dokumentacji użytkownika, nie do naprawy w tym przeglądzie. To samo dla
  `core.worktree` w gołym repozytorium.
- **Kolizja kodów `1` przy `lock`**: przerwanie przez użytkownika, zły argument i
  porażka zapisu w połowie dają ten sam kod. Zmiana wymaga ruszenia zamrożonej
  tabeli — do decyzji człowieka, niżej.
- **Odstępstwo `looks_binary` na końcowym `SUB` (0x1A)** — zapisane wcześniej,
  roadmapa S-08; potwierdzone jako **jedyne** (patrz „Zweryfikowane i czyste").

---

## Zweryfikowane i czyste

Wszystko poniżej **zmierzone**, nie wywnioskowane z lektury.

**Protokół filtra.** Git 2.55 ogłasza `capability=clean`, `smudge` **i `delay`**
(przechwycone szpiegiem pkt-line); nie ogłaszamy `delay`, więc `can-delay` nigdy
nie przychodzi. Kolejność odpowiedzi (`status=success`, flush, treść, flush,
pusta lista, flush) zgadza się z dokumentacją gita co do pakietu. Rozmiary
graniczne przez prawdziwego gita: 0, 1, 65 515, 65 516, 65 517, 131 032, 131 033
bajtów i plik 64 MB — narzut dokładnie 38 bajtów w każdym przypadku, round-trip
przez checkout bajt w bajt (MD5 zgodne). Strumień urwany w środku żądania →
błąd, nie ciche wyjście zerem. Błąd na jednym pliku → `status=error` i sesja
trwa dalej.

**Nietypowe konfiguracje repozytorium, każda komenda.** Poza repozytorium: `2`
dla wszystkich poza `diff` (który z założenia czyta plik, jaki poda git).
Repozytorium gołe: `2`, „this is a bare repository". Repozytorium bez commitów:
wszystko `0`, sensowne komunikaty. Podkatalog: `0`, ścieżki liczone od korzenia.
Podłączony worktree: klucz i rejestracja w `common_dir`, `git add` sekretu z
worktree daje ciphertext, `lock` **odmawia** z listą pozostałych checkoutów.
`--separate-git-dir`: klucz w prawdziwym katalogu gita, wszystko działa. Klon
płytki: `unlock` działa, `status` uczciwie melduje niezbadaną część historii.
Submoduł: własna konfiguracja, `status` mówi wprost, że filtr nie jest
zarejestrowany, `export-key` → `3`. Repozytorium SHA-256 — pokryte przeglądem 1.

**Indeks.** Wersje 2, 3 i 4 przeżywają `forget_stat` i `restage`, a git po nich
commituje **nowy** blob (test pilnuje wyniku `git commit`, nie zawartości
indeksu). Split index → jawna odmowa, nie ciche „zrobione". `index.lock`
trzymany przez kogoś innego → odmowa i ostrzeżenie, nic nie zapisane. Suma
kontrolna weryfikowana przed edycją i przeliczana po; `index.skipHash` zachowane.
`TREE` i `EOIE` usuwane przy `restage` (z zmierzonym powodem), `IEOT`, `REUC`,
`UNTR` i fsmonitor zachowane. Konflikt scalania: wpisy stage 1/2/3 nietknięte,
`git ls-files -u` bez zmian. `intent-to-add`, symlinki (`120000`) i gitlinki
(`160000`) pomijane. Zły rozmiar identyfikatora odrzucany przed jakimkolwiek
zapisem.

**Końce linii — 72 kombinacje wobec prawdziwego gita.** Repozytorium referencyjne
z `* text` i nasze z `*.env text`, dla `core.autocrlf` ∈
{unset, true, false, input, 1, yes, on, 0, no, off, TRUE, Input} × `core.eol` ∈
{unset, lf, crlf, native, LF, CRLF}: **72/72 zgodne**, wynik w katalogu roboczym
identyczny z gitem. Windows wymaga osobnego przebiegu (niżej).

**Tekst kontra binaria — 18 kształtów wobec gita.** ASCII, 2560 B z zakresu
`0x80–0xFF`, 2400 B znaków sterujących, NUL na offsecie 0/7000/1 000 000,
`\x1b\t\x0c\x08`, `\r\r\n`, samotny CR, granica 128:1 i 127:1, BOM UTF-16.
Wszystkie zgodne poza zapisanym wcześniej końcowym `SUB` — **innych odstępstw
nie ma**.

**Ścieżki, cały potok przez prawdziwego gita.** Spacja w środku, spacja wiodąca i
końcowa, znak nowej linii, `"`, `\`, 180-znakowa nazwa, UTF-8 spoza ASCII:
wszystkie zaszyfrowane, wszystkie poprawnie odszyfrowane, `git status` czysty po
`lock`. Symlinki (także wskazujące poza repozytorium) i bit wykonywalny:
git nie filtruje symlinków, `lock` ich nie rusza, `755` przeżywa, plik `444` jest
poprawnie podmieniany. Nazwy nie-UTF-8 nieosiągalne na APFS — luka pokrycia dla
CI na Linuksie.

**`lock` wobec stanów drzewa roboczego.** Konflikt scalania → `2`. Plik
nieśledzony pasujący do wzorca → `2`. `git add -N` → `2`. Zmiana wyłącznie w
końcach linii → przechodzi (treść znormalizowana **jest** w repozytorium).
Zadeklarowany plik usunięty z drzewa → przechodzi (blob w indeksie). Plik tylko
do odczytu → szyfrowany, tryb zachowany.

**Scenariusz akceptacyjny z `zalozenia.md`** — `init`, deklaracja, commit, klon,
`unlock`: treść bajt w bajt, `git status` **czysty**, `lock` po tym też czysty.

---

## Luki pokrycia wymagające CI na innej platformie

Repozytorium nie ma `.github/` w ogóle, więc poniższe nie jest dziś sprawdzane
nigdzie:

- **Windows, cała gałąź `EolMode::Native`.** `cfg!(windows)` występuje raz,
  `src/eol.rs`, i to jest cała ścieżka CRLF; na macOS `apply(_, Native)` to
  `to_vec()`. Do przebiegu: (a) `core.autocrlf=true` pełny cykl — smudge pisze
  CRLF, następny clean normalizuje, `git status` czysty; (b) `core.eol=native` i
  brak `core.eol` → CRLF; (c) `eol=native` w `.git-xcrypt`; (d) `-text` faktycznie
  trzymające konwersję gita z dala od ciphertextu.
- **Windows, uprawnienia pliku klucza.** Każdy test uprawnień jest
  `#[cfg(unix)]` (`keyfile.rs`, `atomic.rs`, `export_key.rs`, `unlock.rs`,
  `lock.rs`, `status.rs`), więc połowa reguły „ACL ograniczone do właściciela"
  jest nieweryfikowana.
- **Windows, `atomic::replace` na pliku tylko do odczytu.** `MoveFileEx` odmawia
  celu z `FILE_ATTRIBUTE_READONLY`; na Uniksie to działa i jest przetestowane.
- **Linux, ścieżki nie-UTF-8.** APFS odmawia takich nazw, więc `decide`,
  `.git-xcrypt` i indeks nigdy nie widziały ich na tej maszynie.
- **Linux, `NAME_MAX` na innych systemach plików** — `MAX_NAME = 255` jest
  podłogą, nie odczytem; egzotyczne systemy plików z niższym limitem nadal
  odpadną.

---

## Do decyzji człowieka

1. **Kod `5` jest przeciążony.** `status` zwraca go również dla
   `undetermined` — klon płytki, klon częściowy, split index, nieczytelny indeks,
   brak `.git-xcrypt`. Zmierzone: w pełni zdrowy `git clone --depth 1` kończy
   `5`, a `actions/checkout` jest domyślnie płytkie, więc **domyślna konfiguracja
   CI nie może przejść tej bramki**. Tabela kodów jest zamrożona i nie ma kodu
   „nie dało się ustalić", więc rozstrzygnięcie jest produktowe: albo nowy kod,
   albo demotowanie płytkiego/częściowego klonu do noty. Pozycja była już
   odnotowana jako otwarta w poprzednich przebiegach; teraz ma pomiar.
2. **Czy `status` ma rozwiązywać atrybuty, zamiast je nazywać (F4).** Pełna
   odpowiedź na „czy git uruchomi filtr dla tej ścieżki" wymaga implementacji
   dopasowania atrybutów gita — praktycznie `gix-attributes`, czyli **nowa
   zależność**. Dziś raport nazywa plik i linię i odsyła do `git check-attr`.
3. **`lock`: kody `1` dla trzech różnych rzeczy** — odmowa użytkownika, błąd
   użycia, porażka zapisu w połowie. Rozróżnienie wymaga ruszenia zamrożonej
   tabeli.
4. **Skrócenie nazwy pliku tymczasowego (F6)** oznacza, że residuum po zabitym
   przebiegu na pliku o nazwie ≥ 224 B może nie zostać zamiecione przez `lock`.
   Alternatywa — odmowa obsługi takich plików — jest gorsza; jeśli jednak
   obietnica „po `lock` nie zostaje żaden plaintext" ma być bezwarunkowa, trzeba
   innego schematu nazw (np. rejestru residuum w `.git/`).
5. **`GIT_CONFIG_PARAMETERS` i `includeIf` w konfiguracji globalnej** — obie
   dziury są w `gix-config`. Domknięcie ich to albo własny parser, albo
   spawnowanie `git config` (zakazane przez wymóg samowystarczalności), albo
   zgłoszenie upstream.
