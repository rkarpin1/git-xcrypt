# Widoczność stanu szyfrowania — krótki plan

> Pełny plan: `context/changes/encryption-status-check/plan.md`

## Co i dlaczego

`git-xcrypt status` odpowiada na największe realne ryzyko produktu: sekret, który
trafił do repozytorium jawnie, zanim zaczął być szyfrowany. Sprawdzenie płytkie
dawałoby fałszywe poczucie bezpieczeństwa, więc skan obejmuje całą osiągalną historię.

## Punkt wyjścia

Po S-01 istnieje parser `.git-xcrypt`, wykrywanie magic i dostęp do konfiguracji.
Po S-02 istnieje sekcja zarządzana w `.gitattributes`. Nie ma żadnej komendy, która
patrzy wstecz.

## Pożądany stan końcowy

W repozytorium z sekretem sprzed konfiguracji komenda wypisuje ścieżkę, commity i
procedurę naprawy zaczynającą się od rotacji sekretu, kończąc się kodem `5`.
W repozytorium czystym kończy się kodem `0` i nadaje się na bramkę CI.

## Kluczowe podjęte decyzje

| Decyzja | Wybór | Dlaczego | Źródło |
| --- | --- | --- | --- |
| Głębokość | Cała osiągalna historia | Sekret usunięty z `HEAD` nadal jest u hostingodawcy | Fundament |
| Koszt skanu | 11 bajtów magic na blob | Bez deszyfrowania; koszt zależy od liczby obiektów | Fundament |
| Naprawa | `--fix` tylko na przyszłość | Przepisanie historii nie cofa wycieku | Fundament |
| Czyszczenie historii | Poza zakresem, raport plus procedura | `purge-history` to element wielkości S-01 | Fundament |
| Sygnał automatyczny | Ostrzeżenie na ścieżce filtra | Filtr to jedyny mechanizm niezależny od klienta | Fundament |
| Cache skanu | Brak | Najpierw pomiar, potem ewentualna optymalizacja | Plan |

## Zakres

**W zakresie:** kompletność konfiguracji, skan całej historii, raport z podziałem
na cztery kategorie, `--fix`, ostrzeżenie przy pierwszym szyfrowaniu pliku.

**Poza zakresem:** czyszczenie historii, cache skanu, wykrywanie sekretów spoza wzorców.

## Architektura

```
status ──► konfiguracja (.git/config + sekcja w .gitattributes)
       ──► przejście po commitach ──► (ścieżka, blob) ──► filtr wzorców
                                                     └──► 11 bajtów magic
       ──► raport: zaszyfrowane / niezaszyfrowane / wyciekło / jawne z wyboru
```

## Fazy w skrócie

| Faza | Co dostarcza | Kluczowe ryzyko |
| --- | --- | --- |
| 1. Konfiguracja | Wykrycie klonu bez `unlock` | Fałszywy spokój przy niekompletnej konfiguracji |
| 2. Skan historii | Odpowiedź na największe ryzyko produktu | Koszt przy dużych repozytoriach |
| 3. `--fix` i ostrzeżenie | Naprawa i sygnał automatyczny | „Naprawiono" odczytane jako „sekret bezpieczny" |

**Wymagania wstępne:** S-02.
**Szacowany nakład:** trzy fazy.

## Otwarte ryzyka i założenia

- Komenda nie znajdzie sekretu, który nigdy nie pasował do żadnego wzorca — granica
  do udokumentowania, nie do ukrycia.
- Koszt skanu na dużym repozytorium nie jest jeszcze zmierzony; brak cache jest
  decyzją tymczasową.
- Ryzyko komunikacyjne `--fix` jest większe niż techniczne.

## Kryteria sukcesu

- Sekret zacommitowany przed konfiguracją zostaje znaleziony, także po usunięciu z `HEAD`.
- Świeży klon bez `unlock` jest wykrywany jako niebezpieczny do zapisu.
- Raport nigdy nie sugeruje, że wyciek został cofnięty.
