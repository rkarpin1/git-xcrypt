# Zamknięcie repozytorium — krótki plan

> Pełny plan: `context/archive/2026-08-04-lock-repository/plan.md`

## Co i dlaczego

`git-xcrypt lock` zamienia pliki objęte wzorcami na postać zaszyfrowaną i usuwa
klucz z repozytorium. Ponieważ `.git/` nie jest wersjonowane, ten klucz jest jedyną
kopią — większość tego elementu to zabezpieczenia, nie sama operacja.

## Punkt wyjścia

Po S-03 istnieje `unlock` przekształcający pliki w miejscu oraz `export-key`.
`lock` jest odwrotnością `unlock` plus usunięciem klucza; kod przekształcania jest
wspólny.

## Pożądany stan końcowy

Komenda pyta o potwierdzenie, wypisuje ostrzeżenie z `key_id`, odmawia przy
niezacommitowanych zmianach i dopiero potem szyfruje pliki i usuwa klucz. `--yes`
pomija pytanie, ale nie pomija sprawdzenia czystości.

## Kluczowe podjęte decyzje

| Decyzja | Wybór | Dlaczego | Źródło |
| --- | --- | --- | --- |
| Potwierdzenie | Interaktywne, wpisane `yes` | Rzadka ścieżka o najwyższym koszcie błędu | Fundament |
| Tryb nieinteraktywny | `--yes` | Konwencja z `apt`/`dnf`; `--force` sugerowałby obchodzenie zabezpieczenia | Fundament |
| Treść ostrzeżenia | `key_id`, nigdy klucz | Klucz zostałby w scrollbacku, logu CI i przy przekierowaniu w drzewie roboczym | Fundament |
| Brudny katalog roboczy | Odmowa, `--yes` nie obchodzi | Inne ryzyko niż utrata klucza, zasługuje na osobną decyzję | Fundament |
| Wykrywanie brudnych plików | Porównanie ciphertextu z blobem | Determinizm czyni to równoważnym porównaniu plaintextów, bez deszyfrowania | Plan |

## Zakres

**W zakresie:** sprawdzenie czystości, ostrzeżenie i potwierdzenie, `--yes`,
szyfrowanie w miejscu, usunięcie klucza.

**Poza zakresem:** automatyczny eksport klucza, wypisywanie klucza, flaga
obchodząca sprawdzenie czystości.

## Architektura

```
lock ──► sprawdzenie czystości (ciphertext vs blob z HEAD)
     ──► ostrzeżenie z key_id + potwierdzenie
     ──► szyfrowanie plików w miejscu (kod wspólny z clean)
     ──► usunięcie klucza  ← dopiero na końcu
```

## Fazy w skrócie

| Faza | Co dostarcza | Kluczowe ryzyko |
| --- | --- | --- |
| 1. `lock` z zabezpieczeniami | Działająca komenda | Odwrotna kolejność operacji zostawiłaby katalog jawny bez klucza |

**Wymagania wstępne:** S-03.
**Szacowany nakład:** jedna faza.

## Otwarte ryzyka i założenia

- Użytkownik może potwierdzić bez czytania; ostrzeżenie jest ostatnią linią obrony.
- Przerwanie w trakcie szyfrowania zostawia mieszany katalog roboczy; ratunkiem
  jest ponowne uruchomienie, bo pliki są samoopisujące po nagłówku.

## Kryteria sukcesu

- `lock` + `unlock` z wyeksportowanym kluczem przywraca treść bajt w bajt.
- Niezacommitowana zmiana blokuje operację nawet z `--yes`.
- W wyjściu komendy nie ma materiału klucza.
