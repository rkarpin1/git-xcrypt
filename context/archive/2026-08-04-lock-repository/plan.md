# Zamknięcie repozytorium — plan implementacji

## Przegląd

`git-xcrypt lock` zamienia pliki objęte wzorcami na ich postać zaszyfrowaną i
usuwa klucz z `.git/git-xcrypt/keys/`. Komenda niszczy jedyną kopię klucza, więc
większość tego planu to zabezpieczenia, a nie sama operacja.

## Analiza stanu obecnego

Po S-03 istnieje `unlock`, który przekształca pliki w miejscu i weryfikuje `key_id`
przed dotknięciem czegokolwiek. `lock` jest jego odwrotnością plus usunięciem
klucza. Kod przekształcania jest wspólny.

## Pożądany stan końcowy

`git-xcrypt lock` pyta o potwierdzenie, wypisuje ostrzeżenie z `key_id`, odmawia
przy niezacommitowanych zmianach, a po potwierdzeniu szyfruje pliki i usuwa klucz.
`--yes` pomija pytanie, ale nie pomija sprawdzenia czystości katalogu roboczego.

### Kluczowe odkrycia

- `.git/` nie jest wersjonowane ani pushowane, więc plik klucza to jedyna kopia.
- Nazwa myli: `unlock` **nie** cofnie `lock` bez pliku klucza.
- Druga, niezależna ścieżka utraty danych: niezacommitowane zmiany w plikach
  objętych wzorcem nie istnieją w żadnym blobie i przepadłyby razem z plaintextem.

## Czego NIE robimy

- Nie eksportujemy klucza automatycznie — `lock` kieruje do `export-key`.
- Nie wypisujemy klucza; ostrzeżenie podaje wyłącznie `key_id`.
- Nie dodajemy flagi obchodzącej sprawdzenie czystości katalogu roboczego.

## Krytyczne szczegóły implementacji

**Kolejność operacji.** Sprawdzenie czystości → ostrzeżenie i potwierdzenie →
zaszyfrowanie plików → **na końcu** usunięcie klucza. Odwrotna kolejność
zostawiłaby katalog roboczy jawny i bez klucza do ponownego zaszyfrowania.

**Wykrywanie brudnego katalogu.** Plik jest brudny, gdy jego zaszyfrowana postać
różni się od bloba w `HEAD`. Porównujemy ciphertext z blobem, a nie plaintext z
plaintextem — determinizm sprawia, że to jest równoważne, a nie wymaga
deszyfrowania bloba.

---

## Faza 1: Komenda `lock` wraz z zabezpieczeniami

### Wymagane zmiany

#### 1. Sprawdzenie czystości katalogu roboczego

**Plik**: `src/commands/lock.rs`

**Cel**: nie dopuścić do utraty niezacommitowanych zmian.

**Kontrakt**: dla każdego pliku objętego wzorcem porównujemy jego zaszyfrowaną
postać z blobem z `HEAD`. Różnica albo brak pliku w `HEAD` → plik jest brudny.
Lista brudnych plików trafia na `stderr`, komenda kończy się kodem `2` i **nic nie
zmienia**. `--yes` tego nie obchodzi.

#### 2. Ostrzeżenie i potwierdzenie

**Plik**: `src/commands/lock.rs`

**Cel**: użytkownik ma zobaczyć, co traci, zanim to straci.

**Kontrakt**: komunikat po angielsku, na `stderr`, zawiera `key_id` w hex, ścieżkę
pliku klucza, zdanie że `unlock` tego nie cofnie oraz gotowe wywołanie
`export-key`. Tryb interaktywny czeka na wpisanie dokładnie `yes`; cokolwiek innego
→ kod `1` i brak zmian. `--yes` pomija pytanie, ale ostrzeżenie i tak jest
wypisywane. Klucz **nigdy** nie jest wypisywany.

#### 3. Zaszyfrowanie i usunięcie klucza

**Plik**: `src/commands/lock.rs`

**Cel**: sama operacja.

**Kontrakt**: pliki objęte wzorcami, które nie zaczynają się od magic, są szyfrowane
w miejscu tym samym kodem co ścieżka clean — wraz z normalizacją końców linii i
ustawieniem bitu `flags`. Pliki już zaszyfrowane są pomijane. Klucz usuwany
dopiero po pomyślnym przetworzeniu wszystkich plików. Brak klucza na wejściu →
kod `3`.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- `lock --yes` w czystym repozytorium szyfruje pliki i usuwa plik klucza
- Po `lock` katalog roboczy zawiera bajty identyczne z blobami z `HEAD`
- `lock` przy niezacommitowanej zmianie kończy się kodem `2`, nie zmienia plików i
  nie usuwa klucza — **także z `--yes`**
- Tryb interaktywny przy wejściu innym niż `yes` kończy się kodem `1` bez zmian
- `stdout` komendy nie zawiera materiału klucza — test szuka bajtów klucza w wyjściu
- Ostrzeżenie zawiera `key_id`
- `lock` bez klucza kończy się kodem `3`
- Po `lock` i `unlock` z wyeksportowanym kluczem treść wraca bajt w bajt
- `lock` uruchomiony dwa razy jest bezpieczny (drugi raz kończy się kodem `3`)
- `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Weryfikacja ręczna

- Ostrzeżenie faktycznie odstrasza: czytelnik rozumie, że traci dostęp do historii
- Tryb interaktywny działa w prawdziwym terminalu

---

## Strategia testowania

### Testy integracyjne

- Pełny cykl: `init` → sekret → commit → `export-key` → `lock` → sprawdzenie, że
  katalog roboczy jest zaszyfrowany i klucza nie ma → `unlock` → treść wraca
- Brudny katalog roboczy z `--yes` i bez
- Odmowa potwierdzenia

## Referencje

- `context/foundation/zalozenia.md` §Zarządzanie kluczami → „Zabezpieczenia `lock`"
- Plan S-03: `context/archive/2026-08-04-key-export-and-unlock/plan.md`

## Postęp

### Faza 1: Komenda `lock` wraz z zabezpieczeniami

#### Automatyczne

- [x] 1.1 `lock --yes` szyfruje pliki i usuwa klucz — 3745a7d
- [x] 1.2 Katalog roboczy po `lock` jest identyczny z blobami z `HEAD` — 3745a7d
- [x] 1.3 Brudny katalog roboczy → kod `2`, brak zmian, także z `--yes` — 3745a7d
- [x] 1.4 Odmowa potwierdzenia → kod `1` bez zmian — 3745a7d
- [x] 1.5 Wyjście nie zawiera materiału klucza — 3745a7d
- [x] 1.6 Ostrzeżenie zawiera `key_id` — 3745a7d
- [x] 1.7 `lock` bez klucza → kod `3` — 3745a7d
- [x] 1.8 `lock` + `unlock` przywraca treść bajt w bajt — 3745a7d
- [x] 1.9 Powtórzony `lock` jest bezpieczny — 3745a7d
- [x] 1.10 `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` — 3745a7d

#### Ręczne

- [x] 1.11 Ostrzeżenie jest zrozumiałe i odstraszające — 3745a7d
- [x] 1.12 Tryb interaktywny działa w prawdziwym terminalu — 3745a7d
