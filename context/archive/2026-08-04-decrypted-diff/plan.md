# Różnice na treści odszyfrowanej — plan implementacji

## Przegląd

`git diff` na pliku szyfrowanym pokazuje dziś szum ciphertextu albo
`Binary files differ`. Ten element podpina `diff=git-xcrypt` przez `textconv`, więc
git porównuje treść jawną.

## Analiza stanu obecnego

Po S-01 istnieje `crypto::decrypt`, wykrywanie magic i konfiguracja filtra pisana
przez `init`. Po S-02 sekcja zarządzana w `.gitattributes` zawiera już
`diff=git-xcrypt` na wzorcach — brakuje wyłącznie sterownika po stronie `.git/config`.

## Pożądany stan końcowy

`git diff`, `git log -p` i `git show` pokazują różnice na treści jawnej dla plików
objętych wzorcami. Bez klucza komenda kończy się czytelnym błędem zamiast
wypisywać szum.

### Kluczowe odkrycia

- `textconv` dostaje **ścieżkę pliku tymczasowego**, nie treść na `stdin` — inaczej
  niż filtr. Wynik idzie na `stdout`.
- `textconv` jest wywoływany również dla treści, która nie jest zaszyfrowana
  (np. commit sprzed konfiguracji), więc musi ją przepuścić, a nie wywalić się.
- Git buforuje wynik `textconv`, gdy ustawione jest `diff.<driver>.cachetextconv`.

## Czego NIE robimy

- Nie zmieniamy formatu ani kryptografii.
- Nie obsługujemy `git difftool` inaczej niż przez ten sam sterownik.
- Nie włączamy `cachetextconv` — bufor trzymałby treść jawną w `.git/`, co jest
  dokładnie tym, czego produkt unika.

## Krytyczne szczegóły implementacji

**`textconv` nie może wywalić się na treści niezaszyfrowanej.** Plik sprzed
konfiguracji, plik pusty i plik binarny bez naszego magic muszą zostać przepuszczone
bez zmian — inaczej `git log -p` przestaje działać na historii repozytorium.

---

## Faza 1: Sterownik `textconv`

### Wymagane zmiany

#### 1. Komenda `diff`

**Plik**: `src/commands/diff.rs`, `src/main.rs`

**Cel**: wejście, które git wywołuje jako `textconv`.

**Kontrakt**: `git-xcrypt diff <ścieżka>` czyta plik ze wskazanej ścieżki. Treść z
naszym magic i zgodnym `key_id` → deszyfrowanie i wypisanie plaintextu na `stdout`.
Treść bez magic → przepuszczenie bez zmian. Brak klucza → kod `3` i komunikat na
`stderr`. Niezgodny `key_id` albo porażka tagu → kod `4`.

#### 2. Rejestracja sterownika

**Plik**: `src/commands/init.rs`

**Cel**: `init` ma rejestrować sterownik razem z filtrem.

**Kontrakt**: `diff.git-xcrypt.textconv` wskazujące na bieżącą binarkę z podkomendą
`diff`. `cachetextconv` **nie** jest ustawiane. Rejestracja jest częścią tej samej
naprawy stanu, którą `init` wykonuje przy istniejącym kluczu.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- `git diff` po zmianie pliku szyfrowanego pokazuje linie plaintextu
- `git log -p` na historii z plikiem sprzed konfiguracji nie kończy się błędem
- `git-xcrypt diff` na pliku bez magic przepuszcza treść bez zmian
- Bez klucza komenda kończy się kodem `3`
- Uszkodzony ciphertext kończy się kodem `4`
- `init` rejestruje `diff.git-xcrypt.textconv` i nie ustawia `cachetextconv`
- `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Weryfikacja ręczna

- `git show` i `git difftool` pokazują treść jawną

---

## Strategia testowania

### Testy integracyjne

- Repozytorium z sekretem, zmiana pliku, `git diff` — sprawdzenie, że wyjście
  zawiera fragment plaintextu i nie zawiera bajtów magic
- `git log -p` obejmujący commit sprzed konfiguracji

## Referencje

- `context/foundation/zalozenia.md` §Integracja z git

## Postęp

### Faza 1: Sterownik `textconv`

#### Automatyczne

- [x] 1.1 `git diff` pokazuje linie plaintextu — 930bbd3
- [x] 1.2 `git log -p` na historii sprzed konfiguracji nie kończy się błędem — 930bbd3
- [x] 1.3 Plik bez magic jest przepuszczany bez zmian — 930bbd3
- [x] 1.4 Brak klucza → kod `3` — 930bbd3
- [x] 1.5 Uszkodzony ciphertext → kod `4` — 930bbd3
- [x] 1.6 `init` rejestruje `textconv` i nie ustawia `cachetextconv` — 930bbd3
- [x] 1.7 `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` — 930bbd3

#### Ręczne

- [x] 1.8 `git show` i `git difftool` pokazują treść jawną — 930bbd3
