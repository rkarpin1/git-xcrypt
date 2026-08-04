# Cztery decyzje właściciela, wykonane

Data: 2026-08-04. Wejście: `review-1-crypto.md`, `review-2-git.md`,
`review-3-completeness.md` — dwanaście pozycji „do decyzji człowieka", z których
właściciel rozstrzygnął cztery. Ten dokument opisuje, co z nich zostało zrobione,
i co się przy tym okazało nieprawdą.

Bramka po całości: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, `cargo deny check licenses` — czysto, **435 testów** (280 `lib` +
155 integracyjnych), wobec 422 przed tym przebiegiem. Cztery commity, po jednym
na decyzję.

| Decyzja | Commit |
| --- | --- |
| 1 — kod wyjścia `6` | `87736eb` |
| 2 — rozstrzyganie atrybutów | `7fb6707` |
| 3 — parytet `looks_binary` (S-08) | `eae1049` |
| 4 — kopia klucza po stronie użytkownika | `33d3081` |

---

## Decyzja 1 — kod wyjścia `6` = „nie dało się ustalić"

**Problem, zmierzony w przeglądzie 2:** `status` zwracał `5` i przy realnej
ekspozycji, i przy `undetermined`. Zdrowy `git clone --depth 1` kończył piątką, a
`actions/checkout` klonuje płytko, dopóki nie dostanie `fetch-depth: 0` — czyli
domyślna konfiguracja CI nie przechodziła bramki, którą ta komenda ma być.

**Zrobione.**

- `src/exit.rs` — nowa stała `UNDETERMINED = 6`, z zapisanym powodem i datą.
  `EXPOSED = 5` znaczy odtąd wyłącznie ekspozycję.
- `src/commands/status.rs` — `Report::exposed() -> bool` zastąpione przez
  `Report::verdict() -> Verdict { Clean, Undetermined, Exposed }`. **Precedencja:
  znalezisko wygrywa z niewiadomą** — przebieg, który jednocześnie znalazł wyciek
  i nie zdołał odczytać indeksu, kończy `5`. `exposed()` zostaje jako cienki
  alias, żeby nie było dwóch spellingów tego samego pytania.
- `src/main.rs` — mapowanie werdyktu na kod wyjścia w jednym miejscu.
- **Komunikaty rozróżniają dwie odpowiedzi bez czytania kodu.** Werdykt
  `undetermined` brzmi
  `VERDICT: undetermined — N thing(s) could not be checked. NOTHING WAS FOUND, and nothing is ruled out either.`,
  a sekcja `undetermined` dopisuje — **tylko gdy jest całą historią**, żeby nie
  osłabiać realnego znaleziska stojącego obok —
  `This is exit code 6, not 5: settle the reasons above and ask again.`
- Dokumentacja: tabela kodów w `zalozenia.md` §Integracja z git (z jawnym
  zapisem, że jest to świadome złamanie zamrożenia, z datą i powodem, oraz z
  odrzuconą alternatywą), `README.md` (tabela + sekcja „Using `status` as a CI
  gate" z `fetch-depth: 0`), `.github/workflows/ci.yml` (blok komentarza dla
  kogoś, kto kopiuje stąd bramkę), `AGENTS.md`.

**Testy** — sześć, każdy zweryfikowany jako czerwony przed zmianą: klon płytki
(zdrowy, po `unlock`), klon częściowy, split index, nieczytelny indeks bez
znaleziska obok, brak `.git-xcrypt`, oraz przypadek precedencji (wyciek +
niewiadoma → `5`). Trzy istniejące testy zmieniły oczekiwanie z `5` na `6`, w tym
`references_that_cannot_be_read_…`, któremu przy okazji poprawiono fixture: miał
w indeksie plik jawny, więc nie odróżniał dwóch werdyktów.

---

## Decyzja 2 — `status` rozstrzyga atrybuty, nie tylko je nazywa

**Problem, zmierzony w przeglądzie 2 (F4):** linia poniżej sekcji zarządzanej,
`.gitattributes` w podkatalogu albo `.git/info/attributes` wyłączają filtr dla
zadeklarowanej ścieżki. `git check-attr filter` mówi wtedy `unset`, `git add`
zapisuje plaintext z kodem `0`, a `status` wypisywał tylko **notę** — nota nie
zapala bramki CI. To była ostatnia droga do zielonego raportu na repozytorium,
które faktycznie nie szyfruje.

**Bilans zależności — przesłanka z zadania okazała się nieprawdziwa, wniosek nie.**
Raport przeglądu 3 (a za nim polecenie) mówił, że `gix-attributes` jest już w
grafie zależności. **Nie było go**: `cargo tree -i gix-attributes` →
`package ID specification 'gix-attributes' did not match any packages`, brak
wpisu w `Cargo.lock`. Faktyczny koszt jest mimo to zerowy w części przechodniej:
`cargo add gix-attributes` daje `Locking 1 package`, bo `bstr`, `gix-glob`,
`gix-path`, `gix-quote`, `gix-trace`, `gix-features`, `smallvec`, `thiserror` i
`unicode-bom` są już w grafie przez `gix-config` i `gix-glob`. Zmierzona różnica
w `cargo tree`: **jeden nowy crate, zero przechodnich**.
`cargo deny check licenses` → `licenses ok`.

**Zrobione.**

- `src/gitattributes.rs` — `FilterResolver` odtwarzający stos gita w jego
  kolejności priorytetów (od najniższego): wbudowane makro `[attr]binary`,
  `core.attributesFile`, `.gitattributes` z korzenia i kolejnych katalogów na
  ścieżce (sortowane po głębokości, bo `Search` dopasowuje listy od ostatniej),
  na końcu `$GIT_DIR/info/attributes`. Makra honorowane tylko tam, gdzie honoruje
  je git. `core.ignorecase` przekładane na `Case::Fold`.
- `FilterAttribute` z wariantami w pisowni `git check-attr` (`git-xcrypt`, obcy
  sterownik, `set`, `unset`, `unspecified`), więc raport cytuje odpowiedź, którą
  użytkownik dostanie od gita, i obie strony nie mogą się rozjechać.
- `src/commands/status.rs` — nowa luka `SetupGap::FilterUnresolved`, wypełniana w
  `inspect_index` dla każdej zadeklarowanej ścieżki, której git nie rozwiązuje na
  nasz sterownik. Kod wyjścia `5`. Komunikat mówi też, czego **nie** naprawi
  `git-xcrypt init`.
- **Bez fałszywych alarmów.** `gitattributes::foreign_filter_sources` usunięte;
  lista plików z liniami `filter` została **notą**, wypisywaną z werdyktem
  rozstrzygnięcia: albo „któraś z nich sięga zadeklarowanej ścieżki — patrz luka
  wyżej", albo „sprawdzone wobec każdej zadeklarowanej ścieżki w indeksie, nic
  śledzonego nie jest przez nie odsłonięte". Repozytorium bez obcych linii nie
  dostaje żadnej noty.
- **Granica zapisana wprost:** rozstrzygamy tylko ścieżki, które indeks już zna.
  Wzorzec, do którego nie pasuje jeszcze żaden śledzony plik, nie ma czego
  rozstrzygać — i nota to mówi.

**Testy.** Pięć integracyjnych (cztery zweryfikowane czerwone przed zmianą):
`.gitattributes` w podkatalogu, `info/attributes`, makro `[attr]`,
`*.psd filter=lfs` który **nie** może zapalić bramki, oraz cisza przy braku
obcych linii. Do tego test porównawczy `the_filter_attribute_is_resolved_exactly_as_git_resolves_it`
— jedenaście kształtów repozytorium, każdy sprawdzony **znak w znak wobec wyjścia
prawdziwego `git check-attr filter`**, łącznie z przypadkami, w których
`info/attributes` filtr z powrotem włącza i w których plik globalny przegrywa z
repozytorium.

**Koszt, zmierzony** (build `--release`, mediana z pięciu przebiegów, `status` w
całości): 10 002 zadeklarowane pliki w 100 katalogach — **18 ms → 22 ms**. Ten
sam zestaw z dodatkowym `.gitattributes` w każdym ze 100 katalogów —
**22 ms → 34 ms**. Koszt rośnie z liczbą plików atrybutów, nie z liczbą ścieżek:
stos budowany jest raz na przebieg. (Poprzedni pomiar z przeglądu 2 — 63 ms —
pochodził z innego kształtu repozytorium i innego stanu cache'u, więc nie jest
porównywalny wprost; powyższe „przed" i „po" zmierzono tą samą metodą na tym
samym repozytorium.)

---

## Decyzja 3 — S-08 przed S-07, parytet `looks_binary` domknięty

**Pomiar odtworzony przed zmianą, na żywym gicie 2.55** (nie z lektury źródeł):
repozytorium tymczasowe, `* text=auto`, treść `a\r\n\x1a` (`61 0d 0a 1a`) → blob
**`61 0a 1a`**. Git znormalizował CRLF, więc uznał plik za tekst. Nasz
`looks_binary` liczył `printable = 1`, `nonprintable = 1`, `0 < 1` → **binarny**.
Rozjazd potwierdzony.

Zmierzone też granice korekty, każda przez to, czy CR przeżył w blobie:

| treść | git |
| --- | --- |
| `a\r\n\x1a` | tekst |
| `a\r\n\x1a\x1a` | binarny — odejmowany jest **jeden** `SUB` |
| `a\x1ab\r\n` | binarny — tylko **ostatni** bajt |
| `a\x01\r\n\x1a` | binarny — korekta jest warta jeden bajt, zużywa ją `0x01` |
| 128 × `A` + `\x01` + CRLF + `\x1a` | tekst |
| 127 × `A` + `\x01` + CRLF + `\x1a` | binarny |

Przypadek bez CR sprawdzony w drugą stronę, przez checkout przy
`core.autocrlf=true`: `\n\x1a` wraca jako `\r\n\x1a` (tekst), `\x01\n\x1a` wraca
bez zmian (binarny). Stąd `saturating_sub` — licznik dochodzi tu do zera, a panic
przy przepełnieniu na ścieżce filtra przewróciłby każdą operację gita, nie tylko
test.

**Zrobione.** Trzy linie w `src/eol.rs::looks_binary`, odpowiednik zamknięcia
`gather_stats`. Dokumentacja funkcji i `zalozenia.md` §Końce linii mówią teraz,
że reguła jest zamrożona **od 2026-08-04, a nie wcześniej**, i opisują co
zmieniono oraz dlaczego musiało to zdążyć przed pierwszym wydaniem.
`roadmap.md`: S-08 → `done`, z odnotowaniem dotrzymanego terminu, w tabeli
`At a glance`, `Streams`, treści elementu, `Backlog Handoff` i `Done`. `S-07`
zostaje jedynym otwartym elementem.

**Testy** — trzy warstwy, wszystkie zweryfikowane jako czerwone przed zmianą:

- `eol::tests::a_trailing_sub_is_forgiven_exactly_as_git_forgives_it` — dokładnie
  ta treść plus każda granica z tabeli wyżej;
- osiem nowych wektorów w `tests/format_vectors.rs::binary_verdicts`, więc reguła
  jest **zamrożona razem z formatem**, a nie tylko przetestowana (żaden z
  dotychczasowych wektorów nie kończył się bajtem `0x1A` — to jest powód, dla
  którego pełny zestaw przechodził zielono mimo rozjazdu);
- `tests/filter_edge_cases.rs::a_dos_end_of_file_marker_is_classified_the_way_git_classifies_it`
  — porównanie z **prawdziwym gitem** na czterech kształtach: repozytorium
  referencyjne z `* text=auto` wydaje werdykt, a nasz blob musi mieć ten sam bit
  0 pola `flags` i ten sam rozmiar plaintextu, plus czysty `git status` po
  checkoucie.

---

## Decyzja 4 — kopia klucza zostaje obowiązkiem użytkownika

Wariant wyłącznie dokumentacyjny, zgodnie z poleceniem: **żadnego nowego kodu**,
w szczególności żadnego przypomnienia w `init`.

**Zrobione.**

- `README.md` — nowa sekcja „The key file is the only copy — back it up
  yourself", bez łagodzenia: `.git/` nie jest wersjonowane ani pushowane, więc
  plik klucza jest jedyną kopią; jego utrata to trwała utrata **każdej wersji
  każdego zaszyfrowanego pliku w każdym commicie i każdym klonie**, bez procedury
  odzyskiwania; kopię robi `export-key` (tryb `0600`); wskazane, gdzie ta kopia
  leżeć **nie może** — w repozytorium, w innym checkoucie, w katalogu gita, w
  logu CI, w scrollbacku. Cztery istniejące zabezpieczenia opisane jako progi
  zwalniające przed przepaścią, nie jako kopia zapasowa.
- `README.md` §Known limitations — brak mechanizmu kopii zapisany jako **świadoma
  granica zakresu v0.1**, a nie luka do domknięcia przed wydaniem.
- `prd.md` §Open Questions poz. 2 — odnotowana decyzja: odpowiedzialność po
  stronie użytkownika, mechanizmu w v0.1 nie ma, wariant przypomnienia w `init`
  rozważony i odrzucony, pytanie **zostaje otwarte na przyszłość**.
  To samo w `roadmap.md` poz. 6 i w `zalozenia.md` §Zarządzanie kluczami.

---

## Co się nie potwierdziło i co warto wiedzieć

1. **`gix-attributes` nie było w grafie zależności**, wbrew przesłance z raportu
   przeglądu 3 powtórzonej w poleceniu. Wniosek („koszt przechodni zerowy")
   został niezależnie zweryfikowany i jest prawdziwy: jeden crate, zero
   przechodnich, licencje czyste. Zapisane w `zalozenia.md` razem z pomiarem.
2. **Decyzja 2 zmieniła kod wyjścia repozytoriów, które wcześniej przechodziły.**
   Repozytorium, w którym `git check-attr filter` mówi `unset` albo
   `unspecified` dla zadeklarowanej ścieżki, kończy teraz `5` zamiast `0`. To
   jest cały sens tej decyzji, ale jest to zmiana zachowania widoczna z zewnątrz
   i warto ją znać przed wpięciem komendy w istniejące CI.
3. **Nota o obcych liniach `filter` przestała się pojawiać w repozytoriach, w
   których nic się nie dzieje.** Poprzednio wypisywała się na każdym przebiegu z
   dowolną linią dotykającą `filter` (np. `*.psd filter=lfs`). Zamiana „alarm na
   obecność linii" na „rozstrzygnięcie wartości atrybutu" jest tym, o co prosiła
   decyzja, ale oznacza mniej tekstu w raporcie zdrowego repozytorium.
4. **Decyzja 3 przesunęła granicę tekst/binarny.** Plik kończący się bajtem
   `0x1A`, zadeklarowany i już zacommitowany **przed** tą zmianą, dostanie przy
   następnym `git add` inny ciphertext niż miał — bo jego plaintext jest teraz
   normalizowany. Poza tym repozytorium takich plików nie ma; dlatego właśnie
   decyzja mówiła „przed pierwszą publiczną binarką", i dlatego po wydaniu ta
   sama poprawka wymagałaby nowego `suite`.
5. **Pomiar 63 ms z przeglądu 2 nie jest bazą dla pomiaru 18 ms → 22 ms.** Inny
   kształt repozytorium i inny stan cache'u. Porównywalna jest wyłącznie para
   „przed/po" zmierzona tu tą samą metodą na tym samym repozytorium.
6. **Pozycje 3–9 i 11–12 z listy dwunastu pozostają nierozstrzygnięte** i nadal
   czekają na właściciela: kolizja kodu `1` przy `lock` i `sync --check`,
   skracanie nazwy pliku tymczasowego, `GIT_CONFIG_PARAMETERS` i `includeIf`,
   `core.ignorecase` wobec normalizacji Unicode, `core.safecrlf`, widoczność
   `stderr` filtra w JetBrains, próg liczbowy dla NFR wydajnościowego,
   podpisywanie artefaktów wydania. Żadna z nich nie została ruszona.
7. **Żaden workflow nadal nie został uruchomiony przez GitHub Actions.** Windows
   i Linux nie mają ani jednego realnego przebiegu, więc wszystkie pomiary w tym
   dokumencie pochodzą z macOS.
