# emi-code-review-auto-fix — przebieg 3 (2026-08-05)

Dwie rundy po trzy etapy, na zamówienie właściciela po tym, jak sześć „leadów"
poprzedniego przebiegu okazało się w połowie prawdziwymi wadami. SHA startowe
`529da8e`, koniec `aa1147b`, gałąź `master`. **17 commitów, 22 naprawy i
domknięcia pokrycia, zero cofnięć.** Zestaw: 107 → 120 testów.

Bramki (macOS Darwin 25.5.0 arm64, git 2.55.0, APFS; zweryfikowane po każdej
rundzie przez agenta i po całości niezależnie w sesji głównej):
`cargo fmt --check` → czysto; `cargo clippy --all-targets -- -D warnings` →
czysto; `cargo test --all-targets` → **120 zdanych, 0 porażek**. `cargo deny
check` niewymagane — zero zmian zależności w przebiegu.

## Runda 1 (agent A, 3 etapy)

**Etap 1 — szeroki skan.** Całość `src/` (13 842 linie). Kandydatów 2, oba
przetrwały B1 — stosunek nietypowy, ale oba zmierzone na żywym gicie przed
naprawą:

- `19bbc56` — **przebieg szyfrowania `lock` bez strażnika worktree.** Trzecie
  okno tej samej klasy co dwa już zamknięte (prompt-plik, prompt-worktree):
  `git worktree add` w trakcie przebiegu (sekundy–minuty przy dużych sekretach)
  → `lock --yes` kod 0, klucz skasowany, `side/secrets/s1.env` jawny. Zmierzone
  na 4000 plikach. Naprawa: powtórna bramka tuż przed `remove_key`.
- `df5dc97` — **zadeklarowany plik pojawiony w tym samym oknie.** Bramka
  czytająca indeks nie widzi pliku nigdy niedodanego. Naprawa: porównanie
  **wyłącznie przybytków** wobec ankiety — całych zbiorów nie wolno, bo sweep
  kasuje residuum z założenia.

Odrzucone 4 (konfiguracja trzymana przez proces — zapisana decyzja; `sub/.git-xcrypt`
— git czyta tylko korzeń; `seen_trees` bez limitu — zapisany dług; `#[cfg(unix)]`
uprawnień — decyzja 15). Koszt bramek zmierzony: mediana `36,7 → 37,2 s` na 4000
plikach, w szumie `fsync`.

**Etap 2 — adwersarz.** Obie własne naprawy obronione mutacją; fałszywa odmowa
nad zamiatanym residuum wykluczona pomiarem; okno skrócone z minut do
mikrosekund, reszta niedomykalna bez blokady drzewa — zapisane, nie przemilczane.

**Etap 3 — kompletność.** `status.rs` i `gitindex.rs` przeczytane w całości
(luka poprzedniego przebiegu domknięta); parser indeksu zmierzony w wersjach
2/3/4 + `skipHash` + split; predykat odmowy zmierzony z obu stron (7 kształtów).

## Runda 2 (agent B, ślepy na raport rundy 1; cele obowiązkowe adwersarza z QC)

**Etap 1 — szeroki skan.** Kandydatów 26 → 13 do naprawy, 11 odrzuconych.
Najcięższe (wszystkie zmierzone przed naprawą, mutacja potwierdzona):

| Commit | Wada |
| --- | --- |
| `0213f80` | **Klucz główny na stdout**: zaszyfrowany plik klucza + textconv → `git log -p` drukował materiał klucza. Odmowa `diff` pytana teraz po obu stronach szyfru |
| `88479f1` | `status` z podłączonego worktree nie widział HEAD głównego → `no findings` nad wyciekiem, kod 0 |
| `a73f822` | nieczytelne `.git/worktrees` czytane jako puste (`.flatten()`) → kod 0 zamiast 6 |
| `46615dd` | predykat konwersji węższy niż git: `text=input` i przedgitowy atrybut `crlf` konwertują, resolver ich nie znał → blob bez `CR`, `git add` kod 0 |
| `f18e2a4` | `[a-]` renderowane jako `[a-A]` (odwrócony zakres) → linia węższa niż filtr, kierunek kosztujący plik |
| `9c424c3` | BOM na początku `.git-xcrypt` → wzorzec nie wybierał niczego, plaintext w bazie obiektów kodem 0 |
| `fe39286` | plik atrybutów dopasowywany po nazwie wpisu zamiast otwierany sondą — na APFS `secrets/.GITATTRIBUTES` był dla gita źródłem, dla resolvera nie |
| `3eb72d4` | panika `import-key` na nagłówku z `€` (granica znaku UTF-8) |
| `39f0952` | `core.bare = 1` czytane jako nie-bare → fałszywa odmowa `lock` |
| `97745e0` | nieczytelny `.git-xcrypt` w `status` → kod 1 bez raportu zamiast 2 |
| `b5c9461` | nagłówek `Untracked` twierdził, że git zapisze jawnie, w repozytorium filtrującym poprawnie |
| `aa1147b` | błąd odświeżenia stat-cache wyrzucał cały raport `unlock` po udanej deszyfracji |

**Etap 2 — adwersarz, cele obowiązkowe.** `19bbc56` i `df5dc97` **obronione**:
wady odtworzone, mutacje czerwienią, fałszywej odmowy brak (zamiecione residuum
= ubytek, ignorowany; kasacja w trakcie = ubytek; rename wielkością liter =
odmowa nad drzewem, które naprawdę się zmieniło — kierunek bezpieczny). Ręczna
rejestracja worktree w teście: **nie przechodzi z niewłaściwego powodu** —
bramka produkcyjna konsultuje wyłącznie wpisy `read_dir`, oba kształty tożsame,
a prawdziwe `git worktree add` pokrywa scenariusz promptu. Zero cofnięć.

**Etap 3 — kompletność.** Dwa domknięcia pokrycia z dowodem nieobecności
strażnika: `acabf97` (śledzony plik o kształcie tymczasowym nie jest zamiatany —
mutacja `sweepable` była zielona na całym zestawie) i `bc55305` (bajt `flags`
w AD bez wektora; próbka magic w `decide.rs` o bajt za krótka).

## Zgodność między rundami

Rundy nie zderzyły się ani razu: runda 2 potwierdziła obie naprawy rundy 1
niezależną mutacją i nie cofnęła niczego. Sprzeczności — brak.

## Co zostało dla człowieka

1. **Systemowy `$(prefix)/etc/gitattributes`** — realne źródło gita (zmierzone
   pod Homebrew), resolver go nie czyta. Naprawa wymaga ścieżki wkompilowanej
   w gita, o którą nie wolno spytać procesem (samowystarczalność); zła zgadnięta
   ścieżka = fałszywe odmowy przy `required = true`. Decyzja właściciela.
2. **Fallback do indeksu dla skasowanego `.gitattributes`** — git na ścieżce
   check-in czyta wtedy kopię z indeksu, resolver tylko drzewo robocze. Zmiana
   projektu resolvera.
3. **`bootstrap_exclusions`** — `secrets/.gitattributes` dostaje w wygenerowanej
   linii `-text diff=git-xcrypt`, leżąc jawnie. Wierna naprawa zmienia każdy
   wygenerowany plik — decyzja.
4. **Asymetria `import-key` vs `unlock`** — import klucza, któremu nagłówki
   przeczą, blokuje potem import właściwego. Pytanie projektowe.
5. **`[[:upper:]]`/`[[:lower:]]` przy zwijaniu** — wejście egzotyczne, wymaga
   weryfikacji semantyki wildmatch.
6. **Niepowtarzalny FAILED w `tests/attributes.rs`** — 2 wystąpienia w tle
   podczas pracy rundy 2 (raz przy drzewie edytowanym w trakcie kompilacji),
   **0 reprodukcji w 13 przebiegach** na stabilnym HEAD (9 agenta + 4 sesji
   głównej). Do obserwacji na CI; bez naprawy bez reprodukcji.

## NIESPRAWDZALNE W TYM ŚRODOWISKU (całość przebiegu)

- Nowe bramki `lock` i sonda `.gitattributes` po nazwie na Windows/NTFS i
  Linux/ext4 — kod przenośny, testy jako parytet z gitem; wykona je macierz CI.
- Synchronizacja testów okna przebiegu na Windows: poll czyta plik podczas
  rename; poprawność zależy od `FILE_SHARE_DELETE` w `std`.
- Margines czasowy testów okna na wolniejszym sprzęcie CI (sygnał = pierwszy
  plik ciphertextem, margines ~450 ms w debug).
- Systemowy plik atrybutów poza prefiksem Homebrew (wymaga roota).
- Widoczność `stderr` filtra w JetBrains (otwarte od S-06, wymaga człowieka).

Testy napisane, a niewykonane przez przebieg: **brak** — każdy nowy test
uruchomiony lokalnie zielono i czerwono pod mutacją; Linux/Windows dopiero na CI.

## Stosunek odrzuconych do naprawionych

15 odrzuconych + 6 nierozstrzygniętych wobec 22 napraw/domknięć. Runda 1 miała
2/2 kandydatów prawdziwych — nietypowe, ale oba z pomiarem na żywym gicie, więc
weryfikacja była realna, nie potwierdzająca. Runda 2: 26 → 13, połowa odpadła.
