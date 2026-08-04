<!-- IMPL-REVIEW-REPORT -->
# Przegląd implementacji: Synchronizacja `.gitattributes` z `.git-xcrypt`

- **Plan**: `context/changes/gitignore-style-config/plan.md`
- **Zakres**: Fazy 1–2 z 2 (obie ukończone)
- **Data**: 2026-08-04
- **Werdykt**: ODRZUCONY po pierwszym przebiegu → ZAAKCEPTOWANY po naprawach
- **Ustalenia**: przebieg 1 — 1 krytyczne, 3 ostrzeżenia, 5 obserwacji

## Werdykty

| Wymiar | Przed naprawą | Po naprawie |
| --- | --- | --- |
| Zgodność z planem | PASS | PASS |
| Dyscyplina zakresu | PASS | PASS |
| Bezpieczeństwo i jakość | FAIL | PASS |
| Architektura | PASS | PASS |
| Spójność wzorców | PASS | PASS |
| Kryteria sukcesu | PASS | PASS |

Bramka jakości po naprawach: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
i `cargo test` (178 testów) przechodzą.

## Ustalenie krytyczne

### F1 — wzorzec katalogowy nie sięgał tak daleko jak filtr, więc `-text` gubiło się dokładnie tam, gdzie chroni

- **Ważność**: ❌ KRYTYCZNE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/gitattributes.rs:108` (przed naprawą)
- **Szczegóły**: `.gitignore` **pływa** wzorcem, który nie ma własnego ukośnika:
  `secrets/` obejmuje także `app/secrets/x`, i tak samo robi `Config::decide`
  (przejście po katalogach nadrzędnych w `config.rs`). Wygenerowana linia
  `secrets/**` ukośnik ma, więc w `.gitattributes` jest **zakotwiczona w
  korzeniu** i nie sięga poza `secrets/…`. Ten sam rozjazd dotyczył wzorca bez
  końcowego ukośnika: `*.env` w `.gitignore` dopasowuje też katalog `a.env`, a
  filtr szyfruje jego zawartość — linia `*.env` w `.gitattributes` obejmuje sam
  plik.

  Dokumentacja modułu nazywała ten kierunek błędu nieszkodliwym („errs narrow").
  **To była błędna ocena.** Brak `-text` jest nieszkodliwy tylko dopóki ratuje
  nas autodetekcja gita po wiodącym NUL; jawny atrybut `text` — a `*.env text`
  we własnym `.gitattributes` użytkownika jest zupełnie zwyczajny — omija
  detekcję i git wykonuje konwersję CRLF **na wyjściu filtra**, czyli na
  ciphertexcie.

  Zmierzone na git 2.55, plik 2 MiB w `app/secrets/deep.env`, wzorzec
  `secrets/`, linia użytkownika `*.env text`:

  | rendering | blob | wynik |
  | --- | --- | --- |
  | `secrets/**` (przed) | 2 097 164 B zamiast 2 097 190 | 26 bajtów `CR` zjedzonych, `git add` kod **0**, commit przechodzi |
  | `**/secrets/**` (po) | 2 097 190 B | round-trip bajt w bajt |

  Przy starym renderingu `git checkout` kończył się
  `authentication failed; the file has been altered` i **plik znikał** —
  plaintext był zniszczony już przy `git add`, które zwróciło zero. Wprost
  przeciw guardrailowi PRD „filtr nigdy nie uszkadza pliku użytkownika".
- **Naprawa**: `translate` zwraca teraz **komplet** pisowni jednego wzorca:
  prefiks `**/` wszędzie tam, gdzie `.gitignore` pływa, plus osobna linia
  `.../**` na poddrzewo katalogu o tej nazwie. Rendering pokrywa dokładnie ten
  zbiór ścieżek, który szyfruje filtr.
- **Testy**: `tests/sync_command.rs::an_encrypted_file_survives_a_users_own_text_attribute`
  (odtwarza uszkodzenie end-to-end; przed naprawą czerwony),
  `a_directory_pattern_reaches_the_subtree_at_any_depth`,
  `src/gitattributes.rs::a_directory_pattern_covers_the_subtree_at_any_depth`,
  `a_file_pattern_also_covers_a_directory_of_that_name`.
- **Decyzja**: NAPRAWIONE

## Ostrzeżenia

### F2 — negacje zostawiały `-text` na plikach trzymanych jawnie

- **Ważność**: ⚠️ OSTRZEŻENIE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/gitattributes.rs:49` (przed naprawą)
- **Szczegóły**: plan i brief rozstrzygały „negacje pomijamy, bo
  `.gitattributes` nie ma dla nich sensownego odpowiednika". Odpowiednik jest:
  `!text !diff`. Bez niego `secrets/README.md` wyłączony negacją zostawał z
  `-text diff=git-xcrypt` odziedziczonym po szerszej linii — czyli git przestawał
  zarządzać końcami linii pliku, który leży w repozytorium jawnie, a po S-05
  `git diff` kierowałby na niego sterownik deszyfrujący. Zmierzone na git 2.55:
  `text: unset, diff: git-xcrypt` przed naprawą, `unspecified` po.
- **Naprawa**: nowy akcesor `Config::negated_patterns()` (tylko odczyt, parser
  nietknięty) i grupa linii `!text !diff` renderowana **na końcu** sekcji, bo git
  bierze ostatnie dopasowanie.
- **Testy**: `tests/sync_command.rs::a_negated_path_gets_gits_defaults_back`,
  `src/gitattributes.rs::a_negation_restores_gits_defaults_for_the_path`.
- **Decyzja**: NAPRAWIONE (świadome odejście od zapisu w planie — powód wyżej)

### F3 — `.gitattributes` i `.git/config` zapisywane nieatomowo

- **Ważność**: ⚠️ OSTRZEŻENIE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/gitattributes.rs:265`, `src/gitconfig.rs:55` (przed naprawą)
- **Szczegóły**: `fs::write` najpierw obcina plik, potem pisze. Awaria między
  jednym a drugim — brak miejsca, zanik zasilania — zostawia plik pusty lub
  skrócony. Pierwszą ofiarą jest linia `* filter=git-xcrypt`, czyli jedyna, na
  której wisi całe bezpieczeństwo; git widzi wtedy brak filtra i następny
  `git add` na sekrecie kończy się kodem `0` z plaintextem w bazie obiektów.
  Ten sam kształt miał zapis `.git/config`, gdzie ginie rejestracja sterownika.
  Dodatkowo obcięcie `.gitattributes` kasuje treść użytkownika spoza markerów,
  którą `upsert` obiecuje zachować.
- **Naprawa**: nowy moduł `src/atomic.rs` — zapis do pliku obok, `sync_all`,
  `rename` na miejsce. Używany przez `gitattributes::write_section` i
  `gitconfig::save_local`.
- **Decyzja**: NAPRAWIONE

### F4 — `binary` przegrywało, gdy szerszy wzorzec stał niżej

- **Ważność**: ⚠️ OSTRZEŻENIE · **Wymiar**: Bezpieczeństwo i jakość · **Lokalizacja**: `src/gitattributes.rs:75` (przed naprawą)
- **Szczegóły**: linie szły w kolejności `.git-xcrypt`, a git rozstrzyga
  ostatnim dopasowaniem. Przy konfiguracji `secrets/key.p12 binary` **przed**
  `secrets/` wygenerowana linia `secrets/key.p12 -text -diff` stała nad
  `**/secrets/** … diff=git-xcrypt`, więc git raportował dla niej
  `diff: git-xcrypt` — dokładnie odwrotnie niż `Decision.suppress_diff`, dla
  którego ta linia powstała.
- **Naprawa**: trzy grupy zamiast jednej listy — linie nadające `diff`, potem
  linie je odbierające, potem negacje. Wewnątrz grupy nadal kolejność wejścia,
  więc wynik pozostaje czystą funkcją konfiguracji.
- **Test**: `a_line_that_takes_something_away_is_rendered_below_every_line_that_grants_it`.
- **Decyzja**: NAPRAWIONE

## Obserwacje

### F5 — markery wykrywane jako podciąg, nie jako cała linia

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/gitattributes.rs:233`
- **Szczegóły**: `contents.find(BEGIN)` trafiał również w komentarz użytkownika
  postaci `# >>> git-xcrypt >>> (legacy)`, więc następny zapis podmieniał
  wszystko od tej linii w dół — utrata treści, którą `upsert` obiecuje zachować.
- **Naprawa**: `marker_line()` dopasowuje marker jako **całą linię** (z tolerancją
  na CRLF). `has_section` celowo zostaje podciągiem: ta funkcja decyduje, czy
  `init` odmówi wygenerowania drugiego klucza, a tam bezpieczny kierunek to
  „zobaczyć ślad, którego nie ma", nie odwrotnie. Asymetria jest udokumentowana.
- **Test**: `a_marker_inside_a_user_comment_is_not_taken_for_the_section`.
- **Decyzja**: NAPRAWIONE

### F6 — wzorzec zaczynający się od `[attr]` stawał się definicją makra

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/gitattributes.rs:156`
- **Szczegóły**: `[attr]` to legalna klasa znaków w `.gitignore`, ale git czyta
  ten prefiks jako definicję makra, **zanim** dojdzie do cudzysłowów. Linia
  `[attr]x -text diff=git-xcrypt` definiowała makro `x` i nie dopasowywała
  niczego. Zmierzone na git 2.55.
- **Naprawa**: taki wzorzec jest cytowany C-stylem, co kieruje git do gałęzi
  wzorca. Pisownia poddrzewa zaczyna się od `**/`, więc jej to nie dotyczy.
- **Decyzja**: NAPRAWIONE

### F7 — nieczytelny `.gitattributes` dawał komunikat bez nazwy pliku

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/gitattributes.rs:281`
- **Szczegóły**: `read_to_string` zgłasza „stream did not contain valid UTF-8"
  jako błąd I/O — użytkownik nie dowiadywał się, o który plik chodzi ani co
  zrobić.
- **Naprawa**: `InvalidData` mapowane na `Error::Config` z nazwą pliku (kod `2`).
- **Decyzja**: NAPRAWIONE

### F8 — `sync --check` dzieli kod `1` z błędem narzędzia

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/main.rs:135`
- **Szczegóły**: nieaktualna sekcja i `Error::Io` kończą się tym samym kodem `1`,
  więc bramka CI nie odróżni ich bez czytania komunikatu. Zamrożona tabela nie ma
  wolnego kodu, a `5` znaczy ekspozycję, którą kosmetyczna sekcja nie jest.
- **Decyzja**: ZAAKCEPTOWANE — kolizja udokumentowana przy `run_sync`; zmiana
  wymagałaby ruszenia zamrożonej tabeli.

### F9 — `sync` działa w repozytorium bez klucza i bez rejestracji filtra

- **Ważność**: 🔍 OBSERWACJA · **Lokalizacja**: `src/commands/sync.rs:45`
- **Szczegóły**: komenda zapisze `* filter=git-xcrypt` również tam, gdzie nic
  innego nie jest skonfigurowane. Niegroźne (niezdefiniowany filtr to dla gita
  brak filtra), a kompletność konfiguracji jest zadaniem `status` z S-06.
- **Decyzja**: ZAAKCEPTOWANE

## Rozjazdy planu wobec stanu kodu

Odnotowane, nie naprawiane w kodzie:

- Plan wskazuje plik `src/attributes.rs`; sekcja zarządzana i `upsert` mieszkają
  od S-01 w `src/gitattributes.rs` i tam trafiła reszta. Drugi moduł rozbiłby
  własność tego samego pliku.
- Plan mówi „wzorce z wiodącym `/` tracą go". Zmierzone: wiodący `/` kotwiczy
  również w `.gitattributes`, a jego usunięcie rozlewa `-text` na pliki
  nieszyfrowane. Wiodący ukośnik zostaje.
- Plan mówi „`binary` daje linię bez `diff`". Samo pominięcie nie wystarcza —
  patrz F4; renderujemy jawne `-diff`, zgodnie z makrem `binary` z gita.
- Plan i brief mówią „negacje pomijamy" — patrz F2.
- **Zmiana kontraktu `init` (S-01)**: `init` renderuje teraz sekcję z
  `.git-xcrypt`, więc nieczytelny plik konfiguracyjny zatrzymuje komendę kodem
  `2` **po** zapisaniu rejestracji sterownika. Naprawa i tak ląduje, a komunikat
  wskazuje wadliwą linię; ten sam plik zatrzymuje każde `git add`.
