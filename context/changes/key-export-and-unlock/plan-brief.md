# Eksport klucza i odblokowanie po klonie — krótki plan

> Pełny plan: `context/changes/key-export-and-unlock/plan.md`

## Co i dlaczego

Przenoszenie klucza repozytorium między maszynami. Realizuje jedyną historyjkę
użytkownika z PRD (US-01): po klonie na nowej maszynie sekrety wracają w postaci
jawnej, identycznej z oryginałem.

## Punkt wyjścia

Po S-01 klucz główny leży w `.git/git-xcrypt/keys/` i nie da się go stamtąd
wyprowadzić. Klon na drugiej maszynie widzi wyłącznie ciphertext i nie ma jak tego
zmienić.

## Pożądany stan końcowy

`export-key` zapisuje klucz do pliku tekstowego, użytkownik przenosi go wybranym
kanałem, `unlock` na drugiej maszynie odszyfrowuje katalog roboczy i uzupełnia
konfigurację filtra. `git status` po `unlock` jest czysty.

## Kluczowe podjęte decyzje

| Decyzja | Wybór | Dlaczego | Źródło |
| --- | --- | --- | --- |
| Format eksportu | Tekstowy, base64 z nagłówkiem | Da się wkleić do menedżera haseł; `key_id` widoczny wzrokowo | Plan |
| Przepisywanie plików | W miejscu | Działa też dla plików niezacommitowanych | Plan |
| Weryfikacja klucza | `key_id` przed pracą | Niezgodny klucz nie rusza ani jednego pliku | Plan |
| Zapis do repozytorium | Zabroniony, kod `2` | Guardrail z PRD: klucz nigdy w repozytorium | Fundament |
| Konfiguracja filtra | `unlock` ją uzupełnia | `.git/config` nie jest wersjonowane, klon jej nie ma | Fundament |

## Zakres

**W zakresie:** przenośny format klucza, `export-key`, `import-key`, `unlock`,
uzupełnianie konfiguracji filtra w klonie.

**Poza zakresem:** `lock` (S-04), koperty odbiorców, rotacja klucza, ochrona pliku
klucza hasłem.

## Architektura

```
maszyna A: .git/git-xcrypt/keys/default ──export-key──► plik tekstowy (base64)
                                                             │ ręczny transfer
maszyna B: git clone ──unlock <plik>──► import klucza ──► konfiguracja filtra
                                    └──► deszyfrowanie plików w miejscu
```

## Fazy w skrócie

| Faza | Co dostarcza | Kluczowe ryzyko |
| --- | --- | --- |
| 1. Format i `export-key` | Klucz w przenośnym pliku | Komenda wydająca klucz to najkrótsza droga do wycieku |
| 2. `import-key` i `unlock` | Działający przepływ US-01 | Przerwanie w połowie zostawia mieszany katalog roboczy |

**Wymagania wstępne:** S-01.
**Szacowany nakład:** dwie fazy.

## Otwarte ryzyka i założenia

- Utrata jedynego pliku klucza to utrata całej historii sekretów — PRD Open
  Question 2 pozostaje otwarte i nie jest rozwiązywane w tym elemencie.
- `unlock` przerwany w połowie zostawia część plików jawnych; ratunkiem jest
  ponowne uruchomienie, co wymaga pomijania plików już odszyfrowanych.

## Kryteria sukcesu

- Kryterium akceptacji z PRD przechodzi automatycznie: klon → `unlock` → treść
  identyczna z oryginałem.
- `git status` po `unlock` czysty.
- Niewłaściwy klucz nie rusza ani jednego pliku.
