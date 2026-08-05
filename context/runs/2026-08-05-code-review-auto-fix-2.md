# emi-code-review-auto-fix — 2026-08-05, przebieg drugi

Parametry: 1 runda × 3 etapy (domyślne). Gałąź `master`, SHA startowe `e1d8114`.

**Środowiska docelowe:** `ubuntu-latest`, `macos-latest`, `windows-latest` (macierz CI)
oraz build na MSRV 1.88. **Środowisko przebiegu:** Darwin arm64, git 2.55.0, rustc 1.97.1,
APFS bez rozróżniania wielkości liter — **jedna komórka z trzech**.

Baza przed przebiegiem: fmt PASS, clippy 0 ostrzeżeń, **91 testów**, `licenses ok`,
obie kompilacje skrośne PASS.

Kontekst wejściowy: zestaw testów przeszedł tego samego dnia redukcję z 466 do 91,
a składnia `.git-xcrypt` została przedefiniowana w `e1d8114` (cudzysłów zamiast
backslasha) i wchodziła w ten przegląd **nieprzejrzana przez nikogo poza autorem**.

## Etap 1 — szeroki skan

**Kandydaci 6 → ustalenia 4.**

| sha | ustalenie |
|---|---|
| `0f65d9e` | **Regresja z `e1d8114`.** Cudzysłowy pozwoliły nazwać plik z wiodącym `!`; filtr go szyfruje, ale git **odrzuca** wygenerowaną dla niego linię `.gitattributes` — sprawdza `!` *po* odcytowaniu, odwrotnie niż makro `[attr]`. Zmierzone end-to-end: sekret 2 666 669 B zapisany jako blob 2 666 672 B (**35 bajtów `CR` zjedzonych z ciphertextu**), `git add` i `commit` kodem 0, checkout kończy `fatal: authentication failed`, plik przepada. `sync --check` i `status` świeciły zielono. |
| `761ce64` | **`lock` kasował jedyną kopię klucza nad żywym jawnym checkoutem.** Listing `.git/worktrees` szedł przez `.into_iter().flatten().flatten()`, więc błąd `read_dir` dawał pustą listę, a pusta lista znaczy „nie ma innych checkoutów". Zmierzone: `chmod 000 .git/worktrees` → `lock --yes` melduje sukces, `../side/secrets/db.env` nadal czyta `TOP SECRET`, `unlock` tam odpowiada „no repository key". |
| `5764eb3` | **`info/attributes` czytane z `git_dir` zamiast `common_dir`.** Zmierzone: przy `secrets/** -filter` w głównym `.git/info/attributes` `git add` w podłączonym worktree kończy 0 i zapisuje `LEAKED SECRET` jawnie, a `status` **stamtąd** kończy `0` — z głównego checkoutu `5`. |
| `6afb7d9` | **Nieczytelna referencja luźna była notą, nie znaleziskiem.** Nota nie rusza kodu wyjścia. Zmierzone: `chmod 000 .git/refs/heads/leak` nad gałęzią z jawnym sekretem → `VERDICT: no findings.`, exit `0` (kontrola: `5`). Ta sama awaria co udokumentowana dla `packed-refs`, jeden plik dalej. |

**Odrzucone (3):** `spell` gubiący wiodący `#` — obalone pomiarem, cytowanie działa;
`unquote` tnący w środku znaku wielobajtowego — obalone, `\` jest ASCII, więc `index+1`
jest granicą znaku; `repo::work_trees` z tym samym wzorcem połykania błędu co ustalenie 2 —
obalone kryterium 5, udokumentowane wprost jako best-effort używane wyłącznie do
*poszerzania* odmowy.

## Etap 2 — adwersarz

**Kandydaci 4 → ustalenia 0. Cofnięć 0.**

Wszystkie cztery naprawy pod ostrzałem się obroniły, każda zweryfikowana mutacją.
Sprawdzone dodatkowo: konfiguracja mieszająca `"!weird.env"`, `!"!weird.env"`, `"!secrets/"`,
`[attr]odd.env` i `*.env` renderuje się bez ostrzeżenia gita; naprawa 4 nie kupiła
uczciwości kosztem fałszywego alarmu (residuum po awarii nadal jest notą, a przebieg ze
znaleziskiem *i* nieczytelną referencją nadal kończy `5` — zapisana precedencja trzyma);
`e1d8114` poza znalezionym `!` bez zastrzeżeń.

**Odrzucone:** luźna referencja podmieniona na katalog — `status` kończy `0`, ale git też
jej nie widzi (`fatal: Needed a single revision`), więc nic nie zostaje nieprzejrzane.

## Etap 3 — kompletność

**Kandydaci 0 → ustalenia 0.** Wszystkie cztery naprawy dostały pokrycie **wplecione
w istniejące scenariusze** — liczba testów została **91**, żaden nowy plik. Żadne pokrycie
nie jest pod `#[cfg]`: dla worktree użyto pliku w miejscu katalogu zamiast `chmod`,
dla referencji — linii w `packed-refs` zamiast bitu uprawnień. Oba trafiają w tę samą
gałąź `match` co pierwotny wyzwalacz i biegną na trzech platformach.

**Nierozstrzygnięte:** `status.rs:793` — `status` w zwykłym repozytorium, które nigdy nie
używało narzędzia, kończy `5`, choć `zalozenia.md` wymienia „brak `.git-xcrypt`" na liście
kodu `6`. Poprawka ruszałaby regułę werdyktu, od której zależą luki naprawdę zapisujące
jawny tekst — do decyzji właściciela.

## Weryfikacja niezależna (sesja główna)

Odtworzyłem sam najostrzejsze twierdzenie, cofając `0f65d9e` do stanu `e1d8114`:

```
PRZED:  !weird.env -text diff=git-xcrypt
        warning: Negative patterns are ignored in git attributes
        !weird.env: text: unspecified   diff: unspecified     ← bez -text
PO:     **/!weird.env -text diff=git-xcrypt
        !weird.env: text: unset         diff: git-xcrypt      ← poprawnie
```

Ścieżka jest szyfrowana przez catch-all, ale bez `-text` — dokładnie ten kształt, który
pozwala gitowi zjeść `CR` z ciphertextu i stracić plik przy checkoucie.

## Kontrola jakości raportu

- **Ścieżka osiągalności:** każde z czterech `DO NAPRAWY` ma konkretną, zmierzoną
  reprodukcję przeciw prawdziwemu gitowi 2.55. ✔
- **Stosunek odrzuconych do naprawionych: 4 : 4.** Skill ostrzega, że stosunek bliski
  jedności bywa oznaką rundy, która potwierdzała własne podejrzenia zamiast je sprawdzać.
  Tu jednak każde ustalenie ma zmierzoną reprodukcję, a najostrzejsze zweryfikowałem
  osobiście — niski stosunek odzwierciedla wąską, dobrze uzasadnioną listę kandydatów,
  nie stemplowanie. Odnotowane, bo to ostatnia runda i nie ma kolejnego adwersarza.
- **Drobna niespójność księgowa:** etap 1 raportuje „kandydaci 6 → ustalenia 4"
  przy trzech odrzuconych (4 + 3 = 7). Nie zmienia werdyktów.
- **Żadna naprawa nie jest przepisaniem działającego kodu** — cztery zmiany zachowania,
  każda z pomiarem, łącznie 243 wstawione linie w 7 plikach, w tym 144 w testach.

## Bilans

| | |
|---|---|
| Commity | `0f65d9e`, `761ce64`, `5764eb3`, `6afb7d9` |
| Kandydaci → ustalenia | 10 → 4 |
| Odrzucone | 4 |
| Nierozstrzygnięte | 1 + lista leadów |
| Cofnięte | 0 |
| Testy | 91 → **91** (pokrycie wplecione, zero nowych plików) |
| Bramki | wszystkie sześć zielone |

## NIESPRAWDZALNE W TYM ŚRODOWISKU

- Zachowanie w czasie wykonania na `windows-latest` i `ubuntu-latest` — kompilacja skrośna
  dowodzi budowania, nie działania. Cztery nowe pokrycia uruchomiła wyłącznie ta maszyna.
- Semantyka wzorców przy rozróżnianiu wielkości liter na Linuksie — APFS tutaj nie rozróżnia,
  więc `selected_only_when_folding_case` sprawdzone tylko po stronie zwijającej.
- Ramię CRLF `EolMode::Native` na prawdziwym Windows — pokryte parametrem `apply_where`,
  nie systemem.
- `read_dir` na pliku pod Win32 — poprawka zależy tylko od „to nie `NotFound`", więc ramię
  odmowy pada tak czy inaczej, ale errno nie zmierzone.
- Build na MSRV 1.88 — lokalnie 1.97.1, niewykonany.

## Co zostało dla człowieka

1. **`status.rs:793`** — kod `5` zamiast `6` w repozytorium bez `.git-xcrypt`; sprzeczność
   między komentarzem w kodzie, `zalozenia.md` i zachowaniem. Poprawka rusza regułę werdyktu.
2. **Leady niezweryfikowane pomiarem**, zgłoszone jako kierunki, nie wady: TOCTOU na worktree
   dodanym w trakcie promptu `lock`; `catch_all_present` jako dowód rejestracji filtra;
   `main_checkout` przy nieparsowalnym configu; sparse index niewidoczny dla `inspect_index`;
   `core.attributesFile` bez rozwinięcia `~/` i bez ścieżki XDG; `config.worktree`
   podłączonego worktree.
3. **`status.rs` (1524 l.) i `gitindex.rs` (998 l.)** przejrzane przez agenta rundy
   fragmentarycznie — w całości czytał je agent pomocniczy, którego wniosków agent rundy
   świadomie nie przyjął bez własnego pomiaru.
