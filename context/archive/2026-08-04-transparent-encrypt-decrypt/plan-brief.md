# Przezroczyste szyfrowanie w jednym repozytorium — krótki plan

> Pełny plan: `context/archive/2026-08-04-transparent-encrypt-decrypt/plan.md`

## Co i dlaczego

Zamieniamy placeholder odwracający bajty na kompletną ścieżkę produkcyjną:
AES-256-SIV, własny format pliku, klucz repozytorium, `init` i filtr gita w
wariancie długożyjącym. To gwiazda przewodnia roadmapy — dopiero po tym elemencie
wiadomo, czy reguła domenowa z PRD w ogóle działa.

## Punkt wyjścia

Istnieje harness testowy na prawdziwych repozytoriach git (F-01) oraz ukryty
`__test-filter`, który odwraca bajty, żeby harness miał co uruchomić. Zależności
to `thiserror` i `tempfile`. Wszystkie decyzje kryptograficzne i formatowe są
zamrożone w `context/foundation/zalozenia.md` — ten plan ich nie wymyśla.

## Pożądany stan końcowy

`git init`, `git-xcrypt init`, wzorzec w `.git-xcrypt`, `git add` i `git commit` —
blob zaczyna się od `\x00GITXCRYPT\x00`, plik w katalogu roboczym jest jawny,
`git status` po checkoucie milczy, a klon bez klucza pokazuje ciphertext.

## Kluczowe podjęte decyzje

| Decyzja | Wybór | Dlaczego | Źródło |
| --- | --- | --- | --- |
| Szyfr | AES-256-SIV (RFC 5297) | Determinizm jest własnością konstrukcji, nie trybem degradacji | Fundament |
| Format | 22 B nagłówka jako AAD + 16 B SIV | Zamrożony; `suite` pozwala zmienić szyfr bez psucia repozytoriów | Fundament |
| Klucz | Klucz główny 32 B + HKDF per suite | Format pliku klucza nigdy się nie zmienia | Fundament |
| Rejestracja filtra | `filter.git-xcrypt.process` | Proces na plik dawał zmierzone 22× spowolnienie | Fundament |
| Końce linii | W tym elemencie, nie w S-02 | Brak przepisywania ciphertextu między etapami | Plan |
| gitoxide | Pojedyncze `gix-*` | Mniejsza binarka i powierzchnia zależności | Plan |
| CLI | `clap` z derive | Osiem komend w sześciu zadaniach | Plan |
| `text=auto` | Odtworzenie reguły gita | Te same pliki co git uzna za tekst | Plan |

## Zakres

**W zakresie:** kryptografia i format, klucz repozytorium, `init` z trzema
regułami detekcji stanu, parser `.git-xcrypt` z pełnym słownikiem konwersji,
heurystyka i konwersja EOL, filtr długożyjący na pkt-line, usunięcie placeholdera.

**Poza zakresem:** `export-key`, `import-key`, `unlock`, `lock` (S-03, S-04),
`sync` i kosmetyczne linie w `.gitattributes` (S-02), `diff` (S-05), `status`
(S-06), koperty odbiorców, rotacja klucza, buforowanie dyskowe wielkich plików.

## Architektura

```
git add ──► filter.git-xcrypt.process (jeden proces na operację)
              │  pkt-line: command=clean, pathname=%f, treść
              ▼
           decide::clean ──► config (.git-xcrypt) ──► eol ──► crypto ──► blob
git checkout ──► decide::smudge ──► crypto ──► eol ──► katalog roboczy
```

Nagłówek jest samoopisujący, więc smudge nie czyta `.git-xcrypt` w ogóle.

## Fazy w skrócie

| Faza | Co dostarcza | Kluczowe ryzyko |
| --- | --- | --- |
| 1. Kryptografia i format | Szyfrowanie, deszyfrowanie, zamrożone wektory | Format jest nieodwracalny po wydaniu |
| 2. Klucz i `init` | Klucz repozytorium, rejestracja filtra | Błąd detekcji stanu nadpisuje klucz |
| 3. Konfiguracja i EOL | Decyzja per plik, normalizacja | Filtr dotyka każdego pliku repozytorium |
| 4. Protokół i sprzątanie | Działający produkt przez prawdziwego gita | Błąd w pkt-line blokuje całe repozytorium |

**Wymagania wstępne:** F-01 (zamknięty).
**Szacowany nakład:** cztery fazy, każda testowalna niezależnie.

## Otwarte ryzyka i założenia

- Promień rażenia błędu filtra to całe repozytorium, nie tylko pliki szyfrowane —
  stąd obowiązkowy test właściwości `passthrough(x) == x`.
- `required = true` na catch-all oznacza, że awaria filtra blokuje każdą operację
  gita; procedura ratunkowa musi trafić do dokumentacji użytkownika.
- API `aes-siv` 0.7 jest jednorazowe, więc plik trafia do RAM w całości.
- ACL pliku klucza na Windows może wymagać osobnego podejścia niż `0600`.

## Kryteria sukcesu

- Blob w bazie obiektów jest zaszyfrowany, katalog roboczy jawny.
- `git status` po checkoucie czysty — dowód determinizmu.
- Filtr zawodzący przerywa `git add` i nie zostawia plaintextu w bazie obiektów.
