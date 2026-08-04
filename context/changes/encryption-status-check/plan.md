# Widoczność stanu szyfrowania — plan implementacji

## Przegląd

`git-xcrypt status` sprawdza kompletność konfiguracji, skanuje całą osiągalną
historię w poszukiwaniu jawnych wersji plików dziś szyfrowanych, naprawia flagą
`--fix` to, co da się naprawić bezpiecznie, a na ścieżce filtra ostrzega przy
pierwszym szyfrowaniu pliku, który już leży w `HEAD` jawnie.

## Analiza stanu obecnego

Po S-01 istnieje parser `.git-xcrypt`, wykrywanie magic i dostęp do konfiguracji
przez `gix-config`. Po S-02 istnieje sekcja zarządzana w `.gitattributes`.
Skanowanie historii wymaga nowej zdolności: przejścia po obiektach repozytorium.

## Pożądany stan końcowy

`git-xcrypt status` w repozytorium z sekretem zacommitowanym przed konfiguracją
wypisuje ścieżkę, listę commitów i procedurę naprawy zaczynającą się od rotacji
sekretu, a kończy się kodem `5`. W repozytorium czystym kończy się kodem `0`.

### Kluczowe odkrycia

- Skan nie wymaga deszyfrowania — wystarczy sprawdzić 11 bajtów magic na początku
  bloba, więc koszt zależy od liczby obiektów, nie od ich rozmiaru.
- Klon bez `init`/`unlock` ma linię catch-all w `.gitattributes`, ale nie ma wpisów
  `filter.git-xcrypt.*` w `.git/config`; git przepuszcza wtedy treść bez filtrowania.
- Granica komendy: odpowiada na pytanie „czy moje deklaracje są egzekwowane", nie
  „czy w repozytorium są sekrety". Plik, który nigdy nie pasował do wzorca, jest
  niewidzialny.

## Czego NIE robimy

- Nie czyścimy historii. `status` raportuje i wypisuje procedurę; natywny
  `purge-history` jest w `Parked`.
- Nie buforujemy wyników skanu — najpierw pomiar, dopiero potem ewentualny cache.
- Nie wykrywamy sekretów spoza wzorców.

## Krytyczne szczegóły implementacji

**`--fix` naprawia wyłącznie przyszłość.** Komunikaty są tu częścią zabezpieczenia:
użytkownik nie może odczytać „naprawiono" jako „sekret jest bezpieczny". Każdy
raport o ekspozycji w historii musi kończyć się zdaniem o rotacji sekretu.

**Ostrzeżenie na ścieżce filtra nigdy nie zwraca kodu niezerowego.** Przy
`required = true` przerwałoby `git add`, a to jest ostrzeżenie, nie błąd.

---

## Faza 1: Kompletność konfiguracji

### Wymagane zmiany

#### 1. Sprawdzenie konfiguracji

**Plik**: `src/commands/status.rs`

**Cel**: wykryć klon, w którym filtr nie jest zarejestrowany.

**Kontrakt**: sprawdzamy obecność `filter.git-xcrypt.process`,
`filter.git-xcrypt.required = true`, `diff.git-xcrypt.textconv` oraz linii catch-all
w sekcji zarządzanej. Brak któregokolwiek → raport na `stdout` z instrukcją
uruchomienia `init` lub `unlock` i kod `5`.

### Kryteria sukcesu

#### Automatyczne

- Świeży klon bez `unlock` daje kod `5` i wskazuje brakujące wpisy
- Repozytorium po `init` daje kod `0`
- Usunięcie `required = true` z konfiguracji jest wykrywane
- `cargo clippy --all-targets -- -D warnings`

---

## Faza 2: Skan historii

### Wymagane zmiany

#### 1. Zależności

**Plik**: `Cargo.toml`

**Kontrakt**: crate'y `gix-*` potrzebne do przejścia po commitach, drzewach i
obiektach — bez brania całego `gix`.

#### 2. Przejście po historii

**Plik**: `src/history.rs`

**Cel**: znaleźć bloby, których ścieżka pasuje do wzorca, a treść nie zaczyna się od magic.

**Kontrakt**: przechodzimy po wszystkich osiągalnych commitach i ich drzewach,
zbierając pary (ścieżka, blob). Odrzucamy ścieżki niepasujące do wzorców z
`.git-xcrypt`. Dla reszty czytamy początek bloba i sprawdzamy magic. Wynik grupujemy
po ścieżce, z listą commitów, w których wystąpiła wersja jawna. Ten sam blob
występujący pod wieloma commitami liczymy raz.

#### 3. Raport

**Plik**: `src/commands/status.rs`

**Cel**: powiedzieć użytkownikowi, co znaleziono i co z tym zrobić.

**Kontrakt**: trzy rozdzielne sekcje — „zaszyfrowane", „powinno być, a nie jest —
teraz w katalogu roboczym lub `HEAD`", „wyciekło w historii". Sekcja czwarta:
ścieżki wyłączone negacją, jako „jawne z wyboru". Przy ekspozycji w historii raport
zawiera gotowe polecenie dla zewnętrznego `git-filter-repo` oraz checklistę
zaczynającą się od rotacji sekretu. Kod `5` przy jakimkolwiek znalezisku.

### Kryteria sukcesu

#### Automatyczne

- Sekret zacommitowany przed dopisaniem wzorca jest wykrywany
- Sekret zacommitowany, a potem usunięty z `HEAD`, nadal jest wykrywany
- Repozytorium, w którym wszystko było szyfrowane od początku, daje kod `0`
- Plik niepasujący do żadnego wzorca nie jest raportowany
- Ścieżki wyłączone negacją są raportowane osobno, nie jako błąd
- Raport zawiera zdanie o rotacji sekretu przed czyszczeniem historii
- `cargo clippy --all-targets -- -D warnings`

---

## Faza 3: `--fix` i ostrzeżenie na ścieżce filtra

### Wymagane zmiany

#### 1. Flaga `--fix`

**Plik**: `src/commands/status.rs`

**Cel**: naprawić to, co da się naprawić bez przepisywania historii.

**Kontrakt**: pliki pasujące do wzorca, a leżące jawnie w katalogu roboczym lub
`HEAD`, są szyfrowane w miejscu tym samym kodem co ścieżka clean, więc od
następnego commita są chronione. `--fix` **nie** dotyka historii i wypisuje to
wprost. Ekspozycja w historii nadal daje kod `5` po użyciu `--fix`.

#### 2. Ostrzeżenie przy pierwszym szyfrowaniu

**Plik**: `src/decide.rs`

**Cel**: automatyczny sygnał w jedynym momencie, w którym jest actionable.

**Kontrakt**: gdy ścieżka clean szyfruje plik po raz pierwszy, sprawdzamy jednym
odczytem obiektu, czy ta sama ścieżka istnieje w `HEAD` jako treść bez magic.
Jeśli tak — ostrzeżenie na `stderr` z odesłaniem do `status`. **Nigdy** kod
niezerowy. Sprawdzenie musi być tanie: pojedynczy odczyt, żadnego przejścia po historii.

### Kryteria sukcesu

#### Automatyczne

- `status --fix` szyfruje pliki leżące jawnie i po nim `git status` pokazuje zmianę
- `status --fix` nie zmienia historii i mówi o tym wprost
- Po `--fix` ekspozycja w historii nadal daje kod `5`
- Pierwszy `git add` pliku obecnego w `HEAD` jawnie wypisuje ostrzeżenie na `stderr`
- To ostrzeżenie **nie** przerywa `git add`
- Ostrzeżenie nie pojawia się dla pliku, którego nie ma w `HEAD`
- `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Ręczne

- Raport nie sugeruje, że po `--fix` sekret jest bezpieczny
- Ostrzeżenie filtra jest widoczne w oknie narzędziowym Git w IDE

---

## Strategia testowania

### Testy integracyjne

- Repozytorium z sekretem zacommitowanym przed konfiguracją; `status` wykrywa
- Sekret usunięty z `HEAD`, ale obecny w historii; `status` wykrywa
- Świeży klon bez `unlock`; `status` wykrywa brak konfiguracji
- `--fix` i sprawdzenie, że historia została nietknięta

## Referencje

- `context/foundation/zalozenia.md` §Zakres MVP → `git-xcrypt status`
- `context/foundation/prd.md` → Open Question 4

## Postęp

### Faza 1: Kompletność konfiguracji

#### Automatyczne

- [x] 1.1 Świeży klon bez `unlock` daje kod `5` i wskazuje braki — 1787073
- [x] 1.2 Repozytorium po `init` daje kod `0` — 1787073
- [x] 1.3 Usunięcie `required = true` jest wykrywane — 1787073
- [x] 1.4 `cargo clippy --all-targets -- -D warnings` — 1787073

### Faza 2: Skan historii

#### Automatyczne

- [x] 2.1 Sekret sprzed dopisania wzorca jest wykrywany
- [x] 2.2 Sekret usunięty z `HEAD` nadal jest wykrywany
- [x] 2.3 Repozytorium szyfrowane od początku daje kod `0`
- [x] 2.4 Plik spoza wzorców nie jest raportowany
- [x] 2.5 Negacje raportowane osobno, nie jako błąd
- [x] 2.6 Raport zawiera zdanie o rotacji sekretu
- [x] 2.7 `cargo clippy --all-targets -- -D warnings`

### Faza 3: `--fix` i ostrzeżenie na ścieżce filtra

#### Automatyczne

- [ ] 3.1 `status --fix` szyfruje pliki leżące jawnie
- [ ] 3.2 `--fix` nie zmienia historii i mówi o tym wprost
- [ ] 3.3 Po `--fix` ekspozycja w historii nadal daje kod `5`
- [ ] 3.4 Pierwszy `git add` pliku jawnego w `HEAD` wypisuje ostrzeżenie
- [ ] 3.5 Ostrzeżenie nie przerywa `git add`
- [ ] 3.6 Ostrzeżenie nie pojawia się dla pliku spoza `HEAD`
- [ ] 3.7 `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Ręczne

- [ ] 3.8 Raport nie sugeruje, że po `--fix` sekret jest bezpieczny
- [ ] 3.9 Ostrzeżenie filtra widoczne w oknie Git w IDE
