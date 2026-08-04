# Synchronizacja `.gitattributes` z `.git-xcrypt` — plan implementacji

## Przegląd

S-01 zostawia w `.gitattributes` jedną statyczną linię `* filter=git-xcrypt`,
na której wisi całe bezpieczeństwo. Ten element dokłada linie **kosmetyczne** —
`-text` i `diff=git-xcrypt` per wzorzec — oraz komendę `sync`, która je regeneruje.

## Analiza stanu obecnego

Po S-01 istnieje: parser `.git-xcrypt` (`src/config.rs`) rozstrzygający selekcję i
atrybuty na dwóch osiach, zapis sekcji zarządzanej w `.gitattributes`
(`src/commands/init.rs`) ograniczonej markerami, oraz szkielet CLI na `clap`.

## Pożądany stan końcowy

Sekcja zarządzana zawiera linię catch-all **oraz** wygenerowane linie kosmetyczne
odpowiadające wzorcom z `.git-xcrypt`. `git-xcrypt sync` regeneruje je po zmianie
konfiguracji i raportuje, czy coś się zmieniło. Nieuruchomienie `sync` nigdy nie
kosztuje sekretu — najwyżej gorszy `git diff`.

### Kluczowe odkrycia

- Rozjazd linii kosmetycznych jest nieszkodliwy: zmierzone, że wiodący NUL w magic
  uruchamia heurystykę binarną gita, więc `-text` jest pasem bezpieczeństwa, a nie
  elementem nośnym (`zalozenia.md` §Końce linii).
- Tłumaczenie `sekrety/` → `sekrety/**` jest potrzebne **wyłącznie** tutaj —
  dopasowaniem na ścieżce filtra zajmuje się `gix-ignore`.
- `binary` wyłącza `diff=git-xcrypt` w wygenerowanej linii, tak jak makro `binary`
  w gicie oznacza `-text -diff`.

## Czego NIE robimy

- Nie ruszamy linii catch-all — jest statyczna i pisana raz przez `init`.
- Nie zmieniamy parsera `.git-xcrypt` — należy do S-01.
- Nie wykrywamy sekretów w historii — S-06.

## Podejście do implementacji

Dwie fazy: najpierw czyste renderowanie sekcji jako funkcja konfiguracji, potem
komenda, która je zapisuje i raportuje różnicę.

---

## Faza 1: Renderowanie sekcji zarządzanej

### Wymagane zmiany

#### 1. Tłumaczenie wzorców

**Plik**: `src/attributes.rs`

**Cel**: przełożyć wzorce z `.git-xcrypt` na składnię, którą git honoruje w `.gitattributes`.

**Kontrakt**: `sekrety/` → `sekrety/**`; wzorce z wiodącym `/` tracą go, bo
`.gitattributes` w korzeniu i tak kotwiczy; negacje **nie** są renderowane, bo
`.gitattributes` nie ma dla nich sensownego odpowiednika w tej roli — pomijamy je
cicho, ponieważ linie są kosmetyczne.

#### 2. Renderowanie sekcji

**Plik**: `src/attributes.rs`

**Cel**: zbudować pełną treść sekcji zarządzanej.

**Kontrakt**: pierwsza linia zawsze `* filter=git-xcrypt`. Dalej po jednej linii na
wzorzec selekcji: `<wzorzec> -text diff=git-xcrypt`, przy czym atrybut `binary`
w `.git-xcrypt` daje `<wzorzec> -text` bez `diff`. Kolejność linii odpowiada
kolejności w `.git-xcrypt`, żeby wynik był deterministyczny.

#### 3. Wstawianie sekcji do pliku

**Plik**: `src/attributes.rs`

**Cel**: podmienić treść między markerami, nie tykając reszty.

**Kontrakt**: markery `# >>> git-xcrypt >>>` i `# <<< git-xcrypt <<<`. Brak sekcji →
dopisujemy na końcu pliku. Sekcja obecna → podmieniamy tylko jej wnętrze.
Uszkodzone markery (otwierający bez zamykającego) → błąd `2`, nigdy zgadywanie.
Operacja jest idempotentna: dwa przebiegi dają identyczny plik.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- `sekrety/` renderuje się jako `sekrety/**`
- `binary` daje linię bez `diff=git-xcrypt`
- Negacje nie trafiają do sekcji
- Treść użytkownika poza markerami zostaje nietknięta
- Dwa przebiegi renderowania dają identyczny plik
- Uszkodzone markery kończą się kodem `2`
- `cargo clippy --all-targets -- -D warnings`

---

## Faza 2: Komenda `sync`

### Wymagane zmiany

#### 1. Komenda

**Plik**: `src/commands/sync.rs`, `src/main.rs`

**Cel**: zregenerować sekcję i powiedzieć użytkownikowi, co się zmieniło.

**Kontrakt**: `git-xcrypt sync` czyta `.git-xcrypt`, renderuje sekcję i zapisuje ją,
jeśli różni się od obecnej. Wypisuje na `stderr`, czy coś zmieniono. Kod `0` w obu
przypadkach. Flaga `--check` nie zapisuje, tylko raportuje: kod `0` gdy sekcja jest
aktualna, `1` gdy nie — do użycia w CI.

#### 2. Wywołanie z `init`

**Plik**: `src/commands/init.rs`

**Cel**: świeża inicjacja od razu daje kompletną sekcję.

**Kontrakt**: `init` po utworzeniu `.git-xcrypt` renderuje pełną sekcję tym samym
kodem co `sync`, zamiast wypisywać samą linię catch-all.

### Kryteria sukcesu

#### Weryfikacja automatyczna

- `sync` po dopisaniu wzorca aktualizuje sekcję
- `sync` uruchomiony dwa razy pod rząd za drugim razem nic nie zmienia
- `sync --check` zwraca `1` przy nieaktualnej sekcji i `0` przy aktualnej
- `init` w świeżym repozytorium generuje sekcję identyczną z tą, którą dałby `sync`
- `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Weryfikacja ręczna

- Komunikat `sync` jasno mówi, czy plik został zmieniony

---

## Strategia testowania

### Testy jednostkowe

- Tłumaczenie wzorców, renderowanie sekcji, wstawianie między markery
- Idempotencja i zachowanie treści użytkownika

### Testy integracyjne

- `init` + dopisanie wzorca + `sync` na prawdziwym repozytorium; sprawdzenie, że
  `git check-attr` widzi `-text` i `diff` na oczekiwanej ścieżce

## Referencje

- `context/foundation/zalozenia.md` §Integracja z git → „Konstrukcja catch-all"
- Plan S-01: `context/changes/transparent-encrypt-decrypt/plan.md`

## Postęp

### Faza 1: Renderowanie sekcji zarządzanej

#### Automatyczne

- [x] 1.1 `sekrety/` renderuje się jako `sekrety/**`
- [x] 1.2 `binary` daje linię bez `diff=git-xcrypt`
- [x] 1.3 Negacje nie trafiają do sekcji
- [x] 1.4 Treść poza markerami nietknięta
- [x] 1.5 Renderowanie jest idempotentne
- [x] 1.6 Uszkodzone markery kończą się kodem `2`
- [x] 1.7 `cargo clippy --all-targets -- -D warnings`

### Faza 2: Komenda `sync`

#### Automatyczne

- [ ] 2.1 `sync` aktualizuje sekcję po dopisaniu wzorca
- [ ] 2.2 Drugi `sync` nic nie zmienia
- [ ] 2.3 `sync --check` zwraca `1` przy nieaktualnej sekcji
- [ ] 2.4 `init` generuje sekcję identyczną z `sync`
- [ ] 2.5 `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`

#### Ręczne

- [ ] 2.6 Komunikat `sync` jasno mówi, czy plik został zmieniony
