# Eksport klucza i odblokowanie po klonie — plan implementacji

## Przegląd

Przenoszenie klucza repozytorium między maszynami: `export-key` zapisuje go do
pliku tekstowego, `import-key` wczytuje, `unlock` odszyfrowuje pliki w katalogu
roboczym. To realizuje jedyną historyjkę użytkownika z PRD.

## Analiza stanu obecnego

Po S-01 istnieje `MasterKey` (32 B), plik klucza w `.git/git-xcrypt/keys/` z
własnym nagłówkiem, `key_id` wyprowadzany przez HKDF, parser `.git-xcrypt` i
funkcje `crypto::encrypt` / `crypto::decrypt`.

## Pożądany stan końcowy

Na maszynie A: `git-xcrypt export-key ~/klucze/repo.key`. Plik przenoszony ręcznie.
Na maszynie B po `git clone`: `git-xcrypt unlock ~/klucze/repo.key` — pliki objęte
wzorcami są jawne, bajt w bajt jak przed commitem, a `git status` jest czysty.

### Kluczowe odkrycia

- Format eksportu jest tekstowy: nagłówek z wersją i `key_id`, potem base64 klucza
  głównego. Pozwala wkleić klucz do menedżera haseł i wzrokowo dopasować go do
  repozytorium.
- `key_id` w nagłówku każdego pliku pozwala `unlock` sprawdzić **przed** pracą, czy
  to właściwy klucz — zamiast wywalić się na tagu przy pierwszym pliku.
- `unlock` przekształca pliki **w miejscu**, nie odtwarza ich z bazy obiektów;
  dzięki temu działa też dla plików jeszcze niezacommitowanych.

## Czego NIE robimy

- `lock` — S-04.
- Koperty odbiorców, klucze per stanowisko, rotacja — poza v0.1.
- Ochrona pliku klucza hasłem — poza zakresem tego elementu.

## Krytyczne szczegóły implementacji

**`export-key` nie może pisać do repozytorium.** Ścieżka docelowa jest
kanonizowana i porównywana z korzeniem drzewa roboczego; zapis w jego wnętrzu to
błąd, nie ostrzeżenie. To jest guardrail z PRD, nie ostrożność.

**`unlock` musi być odporny na przerwanie.** Przekształcanie w miejscu oznacza, że
przerwanie w połowie zostawia część plików jawnych, a część zaszyfrowanych. Każdy
plik jest samoopisujący po nagłówku, więc ponowne uruchomienie `unlock` dokończy
pracę — ale wymaga to, żeby `unlock` pomijał pliki już odszyfrowane zamiast na nich
błądzić.

---

## Faza 1: Format eksportu i komenda `export-key`

### Wymagane zmiany

#### 1. Zależność

**Plik**: `Cargo.toml`

**Kontrakt**: crate do base64 z licencją `MIT OR Apache-2.0`.

#### 2. Format przenośny klucza

**Plik**: `src/keyfile.rs`

**Cel**: postać, którą da się przenieść kanałem tekstowym.

**Kontrakt**: linia nagłówka z nazwą formatu, wersją i `key_id` w hex, potem base64
klucza głównego, potem znak nowej linii. Parser odrzuca nieznaną wersję i
niezgodną długość klucza. Format ma własną wersję, niezależną od wersji formatu
pliku danych.

#### 3. Komenda `export-key`

**Plik**: `src/commands/export_key.rs`

**Cel**: wydać klucz do pliku, nigdy do repozytorium ani na `stdout`.

**Kontrakt**: `git-xcrypt export-key <ścieżka>`. Odmowa, gdy ścieżka leży wewnątrz
drzewa roboczego — kod `2`. Odmowa, gdy plik istnieje, chyba że podano `--force`.
Plik tworzony z uprawnieniami `0600` na Uniksie. Brak klucza → kod `3`. Klucz nigdy
nie trafia na `stdout`.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- Wyeksportowany plik daje się wczytać z powrotem i zwraca ten sam `key_id`
- `export-key` do ścieżki wewnątrz repozytorium kończy się kodem `2` i nie tworzy pliku
- `export-key` w repozytorium bez klucza kończy się kodem `3`
- Plik eksportu ma `0600` (`#[cfg(unix)]`)
- `stdout` komendy jest pusty
- Nieznana wersja formatu eksportu kończy się błędem
- `cargo clippy --all-targets -- -D warnings`

---

## Faza 2: `import-key` i `unlock`

### Wymagane zmiany

#### 1. Komenda `import-key`

**Plik**: `src/commands/import_key.rs`

**Cel**: umieścić przeniesiony klucz w `.git/git-xcrypt/keys/`.

**Kontrakt**: `git-xcrypt import-key <ścieżka>`. Odmowa nadpisania istniejącego
klucza — kod `2`, chyba że `key_id` jest identyczny, wtedy operacja jest pustym
sukcesem. Zapis z `0600`.

#### 2. Komenda `unlock`

**Plik**: `src/commands/unlock.rs`

**Cel**: odszyfrować katalog roboczy po klonie.

**Kontrakt**: `git-xcrypt unlock [<ścieżka-do-klucza>]`. Z argumentem — importuje
klucz, potem odszyfrowuje; bez argumentu — używa klucza już obecnego w repozytorium.
Przechodzi po plikach drzewa roboczego objętych wzorcami z `.git-xcrypt`, pomija
te, które nie zaczynają się od magic, i sprawdza `key_id` przed przetworzeniem
czegokolwiek. Niezgodny `key_id` → kod `4` i **żaden plik nie jest ruszony**.
Po odszyfrowaniu stosuje końcówki linii zgodnie z bitem `flags` i konfiguracją gita.

#### 3. Rejestracja filtra przy `unlock`

**Plik**: `src/commands/unlock.rs`

**Cel**: klon nie ma wpisów `filter.git-xcrypt.*`, bo `.git/config` nie jest wersjonowane.

**Kontrakt**: `unlock` uzupełnia brakujące wpisy w konfiguracji tym samym kodem co
`init`, zanim odszyfruje cokolwiek. Bez tego następny `git add` przepuściłby plaintext.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- Pełny przepływ US-01: repozytorium z sekretem → `export-key` → klon → `unlock` →
  treść bajt w bajt równa oryginałowi
- `git status` po `unlock` jest czysty
- `unlock` z niewłaściwym kluczem kończy się kodem `4` i nie zmienia żadnego pliku
- `unlock` uruchomiony dwa razy pod rząd jest bezpieczny (drugi raz nic nie robi)
- `unlock` uzupełnia `filter.git-xcrypt.*` w świeżym klonie
- `import-key` z identycznym kluczem jest pustym sukcesem; z innym daje kod `2`
- Klon bez `unlock` pokazuje ciphertext
- `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Weryfikacja ręczna

- Komunikat przy niezgodnym `key_id` mówi, którego klucza brakuje

---

## Strategia testowania

### Testy integracyjne

- Kryterium akceptacji z PRD: init → sekret → commit → klon → unlock → porównanie
- Klon bez klucza, `unlock` z błędnym kluczem, `unlock` powtórzony

## Referencje

- `context/foundation/prd.md` → US-01
- `context/foundation/zalozenia.md` §Zarządzanie kluczami

## Postęp

### Faza 1: Format eksportu i `export-key`

#### Automatyczne

- [x] 1.1 Round-trip formatu eksportu zachowuje `key_id` — afde7b2
- [x] 1.2 `export-key` do wnętrza repozytorium kończy się kodem `2` bez tworzenia pliku — afde7b2
- [x] 1.3 `export-key` bez klucza kończy się kodem `3` — afde7b2
- [x] 1.4 Plik eksportu ma `0600` (`#[cfg(unix)]`) — afde7b2
- [x] 1.5 `stdout` komendy jest pusty — afde7b2
- [x] 1.6 Nieznana wersja formatu eksportu kończy się błędem — afde7b2
- [x] 1.7 `cargo clippy --all-targets -- -D warnings` — afde7b2

### Faza 2: `import-key` i `unlock`

#### Automatyczne

- [x] 2.1 Pełny przepływ US-01 daje treść bajt w bajt równą oryginałowi
- [x] 2.2 `git status` po `unlock` jest czysty
- [x] 2.3 `unlock` z niewłaściwym kluczem daje kod `4` i nie zmienia plików
- [x] 2.4 Powtórzony `unlock` jest bezpieczny
- [x] 2.5 `unlock` uzupełnia `filter.git-xcrypt.*` w klonie
- [x] 2.6 `import-key` z identycznym kluczem to pusty sukces, z innym kod `2`
- [x] 2.7 Klon bez `unlock` pokazuje ciphertext
- [x] 2.8 `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Ręczne

- [x] 2.9 Komunikat przy niezgodnym `key_id` jest zrozumiały
