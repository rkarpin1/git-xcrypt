# emi-code-review-auto-fix — przebieg 4 (2026-08-06)

Jedna runda, trzy etapy, z **zadanymi kandydatami**: sześć pozycji z sekcji
„Co zostało dla człowieka" przebiegu 3 weszło prosto do Fazy B1, na zlecenie
właściciela. SHA startowe `bfbe94f`, koniec `dd4890b`, gałąź `master`.
**9 commitów, zero cofnięć.** Zestaw: 120 → 122 testy.

Bramki (macOS Darwin 25.5.0 arm64, git 2.55.0 Homebrew, APFS; zweryfikowane
przez agenta i niezależnie w sesji głównej): `cargo fmt --check` → czysto;
`cargo clippy --all-targets -- -D warnings` → czysto; `cargo test
--all-targets` → **122 zdane, 0 porażek**. Zależności nietknięte.

## Werdykty — sześć kandydatów

| # | Kandydat | Werdykt | Commit |
| --- | --- | --- | --- |
| 1 | systemowy `$(prefix)/etc/gitattributes` | **zapisana świadoma granica** | `af3845d` |
| 2 | fallback do indeksu dla skasowanego `.gitattributes` | **WADA — naprawiona** | `aec024c`, `5a37aa6` |
| 3 | `bootstrap_exclusions` na jawnym `secrets/.gitattributes` | **ODRZUCONE** (pomiar: zero szkody) | `5fc0a1f` (zapis granicy) |
| 4 | asymetria `import-key` vs `unlock` | **WADA — naprawiona** | `3708fbe` |
| 5 | `[[:upper:]]`/`[[:lower:]]` przy zwijaniu | **WADA — naprawiona** | `e1bf876`, `fa4fec7` |
| 6 | niepowtarzalny FAILED w `tests/attributes.rs` | **mechanizm znaleziony — naprawiony** | `dd4890b` |

### 1. Plik systemowy — dlaczego granica, nie naprawa

Brakujący fakt zdobyty pomiarem: ścieżka jest **wkompilowana w build gita**
i nie wynika z niczego dostępnego bez spawnu. `GIT_EXEC_PATH`, który git
przekazuje filtrowi, prowadzi do **złej** ścieżki na obu gitach tej maszyny
(Homebrew: `/opt/homebrew/opt/git/etc/…` zamiast `/opt/homebrew/etc/…`;
Apple: analogicznie). Jedyna pewna droga to `git var GIT_ATTR_SYSTEM` — spawn,
zakazany przez samowystarczalność. Zgadnięta zła ścieżka = fałszywe odmowy przy
`required = true` we **wszystkich** repozytoriach maszyny. Domyślnie plik nie
istnieje w żadnej zbadanej instalacji. Oba warianty z kosztami w
`zalozenia.md`; ucieczka użytkownika (`GIT_ATTR_NOSYSTEM=1`) w `README.md`
§Known limitations.

### 2. Fallback do indeksu — najcięższe znalezisko przebiegu

Git na ścieżce check-in czyta kopię `.gitattributes` **z indeksu**, gdy plik
zniknął z drzewa; resolver czytał tylko drzewo. Zmierzone końcem do końca:
`secrets/** text` w kopii indeksowej + `rm .gitattributes` → odmowa filtra
znika, `git add` kod 0, z bloba zjedzone bajty `CR`, plik nie do odzyskania.
Sekwencja osiągalna przez **własny komunikat odmowy** (użytkownik kasuje cały
plik zamiast linii). Naprawa: `gitattributes::staged_fallbacks` — kopie
indeksowe plików nieobecnych w drzewie, plik w drzewie wygrywa (zmierzone),
wszystko nieczytelne → puste (predykat nie może urosnąć o fałszywą odmowę).
Koszt: 70 ms → 70 ms (2000 plików). Dedup dla dwóch pisowni pod
`core.ignorecase` preferuje nazwę bajtowo dokładną — kierunek zmierzony na
gicie.

### 4. `import-key` — odmowa dowodowa zamiast martwego końca

Import złego klucza do świeżego klona przechodził (nic nie kolidowało);
właściwy klucz trafiał potem na odmowę nadpisania z fałszywym w tym stanie
zdaniem o utracie danych. Naprawa w duchu `unlock`: ta sama ankieta nagłówków
(współdzielone funkcje), pytana tylko gdy klucz byłby instalowany; zły klucz —
kod 4 z nazwą pliku, właściwy importuje się czysto, drzewo bez szyfrowanych
plików przyjmuje dowolny.

### 5. Klasy POSIX — ta sama klasa wady co `[a-]`

`gix-glob` pod `Case::Fold` pozwala `[[:upper:]]` przyjąć małą literę, więc
filtr szyfrował `xdir/a.env` pod `[[:upper:]]dir/` — a skopiowana dosłownie
klasa odpowiadała w gicie `unspecified`: **linia węższa niż filtr**, kierunek
kosztujący plik. Naprawa: `fold_case` emituje `[[:upper:][:lower:]]` (negacje
spójnie); parytet przypięty testem porównawczym z żywym `git check-attr`.

### 6. Flake — mechanizm, nie zaklinanie

Test diagnozy smudge mutował **cały** blob (`0x0a→0x0b`), łącznie z 8 losowymi
bajtami `key_id` w nagłówku. Gdy świeży klucz miał tam `0x0a` (≈3% przebiegów),
smudge mówił „obcy klucz" zamiast „altered" i asercja padała. Dowód
deterministyczny w obie strony: seed z `0x0a` w `key_id` → czerwień za każdym
razem; seed bez → zieleń. Naprawa: fixtura na stałym kluczu (SIV
deterministyczny ⇒ identyczne bajty w każdym przebiegu). Po naprawie 10/10.

## Adwersarz i kompletność

Podejrzenie fałszywej odmowy przy naprawie 2 rozstrzygnięte pomiarem — pierwsza
„odmowa nad zdrowym plikiem" okazała się poprawną odmową z racy-clean gita, a
test strony bezpiecznej używa dlatego `update-index --cacheinfo`. Żadna naprawa
nie zmienia bajta istniejących ciphertextów. Wszystkie strażniki z dowodem
mutacją. Zapisy decyzji zaktualizowane (`zalozenia.md`, `README.md`).

## Co zostało dla człowieka

- Uwaga porządkowa: commit `af3845d` zawiera też bullet o fallbacku indeksowym,
  którego jego komunikat nie wymienia — treść poprawna, granica commita
  niedoskonała.
- Ścieżka checkout gita czyta atrybuty najpierw z indeksu nawet przy obecnym
  pliku; nasz resolver wszędzie trzyma semantykę check-in — dotyczy wyłącznie
  jakości komunikatu diagnozy po padłym tagu, zostawione świadomie.

## NIESPRAWDZALNE W TYM ŚRODOWISKU

- Fallback indeksowy i dedup na Windows/NTFS i Linux/ext4 — testy jako parytet
  z gitem, wykona macierz CI.
- `read_attr_from_index` gita dla wpisu-symlinka w indeksie (pomijamy przez
  `holds_content`; kierunek bezpieczny).
- Plik systemowy poza prefiksem Homebrew (wymaga roota).

Testy napisane, a niewykonane: brak — każdy uruchomiony zielono i czerwono pod
mutacją; Linux/Windows na CI.

## Stosunek odrzuconych do naprawionych

Kandydaci byli wstępnie przesiani przez poprzedni przebieg, więc proporcja
4 naprawy : 1 odrzucenie : 1 granica jest oczekiwana, nie podejrzana. Sekcja
„Co zostało dla człowieka" przebiegu 3 jest tym samym **pusta** — wszystkie
sześć pozycji ma werdykt.
