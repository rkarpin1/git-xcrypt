---
project: "git-xcrypt"
version: 1
status: active
created: 2026-08-03
updated: 2026-08-17
prd_version: 1
main_goal: learn
top_blocker: decisions
---

# Roadmap: git-xcrypt

> Wywiedzione z `context/foundation/prd.md` (v1) + sonda bazy kodu z 2026-08-03.
> Edytuj na miejscu; archiwizuj po zastąpieniu.
> Elementy są wymienione w kolejności zależności. Tabela `At a glance` to indeks.
> Nagłówki sekcji i etykiety pól są po angielsku, bo `/10x-archive` dopasowuje je dosłownie przy zamykaniu elementów. Treść jest po polsku.

## Vision recap

Pojedynczy deweloper trzyma sekrety swoich projektów poza repozytorium i kopiuje je ręcznie między maszynami. Ból uderza przy klonie na nowej maszynie, przy zmianie sekretu wymagającej synchronizacji i przy zakładaniu każdego nowego projektu.

Produkt rozstrzyga na podstawie wzorców ścieżek, które pliki opuszczają maszynę wyłącznie w postaci zaszyfrowanej, i gwarantuje, że ta sama treść zawsze daje ten sam ciphertext. Wyróżnikiem wobec projektów bazowych jest samowystarczalna binarka bez zależności od systemowego `gpg`.

## Current state

Wersja v0.1 jest wydana. Roadmapa zawiera wyłącznie pracę poza v0.1, która pozostaje do podjęcia.

## At a glance

| ID    | Change ID                    | Outcome (użytkownik może …)                                             | Prerequisites | PRD refs               | Status   |
| ----- | ---------------------------- | ----------------------------------------------------------------------- | ------------- | ---------------------- | -------- |
| S-09  | per-user-keys                | otworzyć sklonowane repozytorium **własną globalną identity** oraz przekazać capability odbiorcy bez wspólnego keyfile | S-10          | §Access Control, FR-008 | blocked  |
| S-10  | forward-key-rotation         | używać wielu kluczy, bezpiecznie wybrać aktywny klucz i rotować go bez przepisywania historii | S-03          | poza v0.1              | todo     |
| S-11  | rewrite-history-key-rotation | przepisać historię nowym kluczem i opublikować ją force-pushem           | S-10          | poza v0.1, awaryjne    | blocked  |

### S-09: Obsługa kluczy użytkowników

> **Current contract — 2026-08-17.** Ten blok zastępuje wcześniejsze szczegóły implementacyjne poniżej, jeśli są z nim sprzeczne. Pełne uzasadnienie i proponowany układ plików zapisano w `context/foundation/krytyka.md` §`Proposed Operating Model and File Layout`.

- **Outcome:** odbiorca odblokowuje klon własną, globalnie chronioną private identity; repozytorium przechowuje wyłącznie wersjonowany manifest i publiczne koperty dla recipientów. Nie przekazuje się współdzielonego keyfile jako normalnego modelu pracy zespołowej.
- **Prerequisites:** S-10. Multi-key keyring, manifest, `active_key_id` i local runtime state muszą istnieć przed providerem identity i kopertami.
- **Authority and semantics:** przyjmujemy capability model. `add-recipient` domyślnie daje full grant do wszystkich kluczy wymaganych przez oficjalną historię albo odmawia. `remove-recipient` usuwa wyłącznie z przyszłego rosteru; odcięcie od przyszłych danych wymaga `rotate-key --remove-recipient`.
- **Runtime boundary:** filtr nie odczytuje kopert z bieżącego worktree jako jedynego źródła prawdy. Współdzielony przez linked worktrees local runtime state w Git common dir jest związany z digestem kanonicznego manifestu; jego niezgodność powoduje walidację albo odmowę, nigdy użycie starego keyringu na próbę.
- **Identity boundary:** private identity mieszka poza repozytorium i poza `.git/`, w globalnym magazynie użytkownika, agencie/providerze albo systemowym keystore. Fallback plikowy jest jawny, raportuje faktyczną ochronę i nie uzasadnia pełnego wsparcia Windows bez decyzji o ACL/keystore.
- **Versioned state:** `.git-xcrypt-keys/` zawiera kanoniczny manifest (`repo_id`, `generation`, `active_key_id`, wymagane pełne fingerprinty i roster) oraz koperty `(identity_id, full key fingerprint)`. Payload koperty wiąże `repo_id`, pełne identity ID, pełny fingerprint i blobowy `key_id`; nazwy plików nie są zaufaną metadaną.
- **Status:** blocked. Zanim element przejdzie do planowania, otwarte decyzje z `krytyka.md` o globalnym magazynie identity i Windows ACL muszą dostać jawny kontrakt.

- **Outcome:** użytkownik otwiera sklonowane repozytorium **własnym** kluczem prywatnym, zamiast przenosić na maszynę keyring repozytorium. Każdy klucz w keyringu leży w katalogu `.git-xcrypt-keys/` zaszyfrowany osobno dla każdego uprawnionego.
- **Change ID:** per-user-keys
- **PRD refs:** §Access Control (dziś: „jeden ręczny transfer na maszynę"), FR-008
- **Prerequisites:** S-10
- **Parallel with:** —
- **Blockers:** S-10; format koperty i lokalizacja zainstalowanego materiału odblokowującego są rozstrzygnięte. Otwarte pozostają jedynie nazwy komend oraz ergonomia tworzenia i przenoszenia tożsamości użytkownika.
- **Zapisany 2026-08-11 na prośbę właściciela**, przeniesiony z `## Parked`. **To zapis zamiaru, nie harmonogram** — nic tu nie jest zaplanowane na konkretne wydanie. PRD wymienia zarządzanie odbiorcami w §Non-Goals, ale ten zapis dotyczy **v0.1**; element leży poza nią i nie jest z nim sprzeczny.
- **Co już istnieje, i jest tego mało:** zarezerwowana nazwa katalogu `.git-xcrypt-keys` (`src/git/repo.rs:17`), wraz z tym, że nigdy nie jest szyfrowany i że sekcja zarządzana renderuje mu wykluczenie. Ani jednej linii kopert.
- **Czego robić nie trzeba, i to jest tu najważniejsze:** **format pliku danych jest gotowy i nie zmienia się ani o bajt.** Koperta pakuje 32-bajtowy **klucz główny**, więc jest niezależna od suite'a i od formatu bloba, a `key_id` — w zamrożonym nagłówku, w AAD — identyfikuje właśnie klucz główny, więc wiele kluczy w jednym repozytorium i rotacja też mieszczą się bez nowego `suite`. Blob sam mówi, którym kluczem go otwierać.
- **Ustalony model — bez dwóch trybów produktu.** Szyfrowanie blobów, format danych i keyring są wspólne. W `.git/git-xcrypt/keys/` leży zawsze jeden materiał odblokowujący: bezpośredni klucz/keyring repozytorium albo zainstalowana dla tego repozytorium prywatna tożsamość użytkownika. Pierwszy zachowuje obecne `export-key` / `unlock <plik>`; drugi otwiera koperty z `.git-xcrypt-keys/`, a uzyskany klucz repozytorium istnieje tylko w pamięci filtra. `lock` usuwa oba warianty z `.git/`, więc koperty same nie odblokowują checkoutu.
- **Zakres — co konkretnie trzeba zmienić.** Zapis jest po to, żeby ktoś sięgający po ten element nie odkrywał w połowie roboty wspólnego modelu oraz granic `lock` i `export-key`.
  - **Do zbudowania od zera:**
    1. **Tożsamość użytkownika** — para kluczy na osobę, z nowym **zamrożonym** formatem (odrębne magic, bajt wersji i wektory). Prywatna połowa jest po `unlock` instalowana w `.git/git-xcrypt/keys/` danego repozytorium, a jej kopia źródłowa/przenośna pozostaje obowiązkiem użytkownika. Problem transportu **nie znika, tylko przesuwa się o poziom wyżej**: zamiast pliku klucza repozytorium trzeba przenieść tożsamość. Na Windows odziedzicza ten sam problem ACL co dzisiejszy klucz repozytorium.
       - **`identity_id` — rozstrzygnięte 2026-08-16.** Identyfikatorem jest pełny 32-bajtowy klucz publiczny `crypto_box`, zakodowany kanonicznie jako 64 małe znaki hex; opcjonalny stały prefiks formatu może go odróżniać od innych identyfikatorów w komunikatach. Nie używamy UUID, nazwy użytkownika ani skrótu kryptograficznego: pełny klucz jest już publiczny, ma właściwą długość i wiąże identyfikator z materiałem, którym faktycznie pieczętowana jest koperta. Nazwa użytkownika jest wyłącznie powtarzalną etykietą. Parser zawsze wylicza `identity_id` ponownie z klucza publicznego i odmawia, gdy nazwa katalogu, pole pliku lub koperta podają inne ID. Repozytorium i formaty przechowują pełne ID; skrócone ID wolno przyjmować tylko w interfejsie człowieka i tylko wtedy, gdy rozwiązuje się jednoznacznie. Skopiowanie tej samej prywatnej tożsamości na drugą maszynę zachowuje ID, bo jest to ta sama tożsamość; niezależnie odwoływalne urządzenie wymaga nowej pary kluczy.
       - **Tworzenie tożsamości — rozstrzygnięte 2026-08-16.** Składnia to `git-xcrypt identity generate <LABEL> <DIRECTORY>`, np. `git-xcrypt identity generate "Robert/Laptop" D:\\Robert`. Oba argumenty są obowiązkowe. `LABEL` jest metadaną dla człowieka, może się powtarzać i nie jest składnikiem uprawnień, ale jego czytelna postać **wchodzi do nazw obu plików**; pełne `identity_id` pozostaje w ich zawartości i w kopertach, gdzie służy maszynie, zamiast obciążać nazwę nic niemówiącym użytkownikowi ciągiem. Znaki niedozwolone w nazwach plików na wspieranych platformach, w tym `/` z przykładu, wymagają jednego przenośnego kodowania ustalonego razem z rozszerzeniami. `DIRECTORY` wskazuje katalog docelowy, w którym komenda atomowo tworzy dwa rozróżnialne pliki — prywatną tożsamość oraz publiczną część do przekazania administratorowi repozytorium. Powtórzenie etykiety, którego wynikowa nazwa już istnieje, powoduje odmowę zamiast zastąpienia pliku albo dopisania ID. Materiał prywatny nigdy nie trafia do repozytorium ani na `stdout`.
    2. **Format koperty** — `sealed(klucz główny)` plus identyfikator odbiorcy, zamrożony tak samo; mechanizm jest rozstrzygnięty na `crypto_box`.
    3. **Układ katalogu `.git-xcrypt-keys/`** — koperta dla każdego odbiorcy i każdego `key_id`, do którego ma mieć dostęp. Wprowadza w tym produkcie nową klasę zachowania: komendę, która **brudzi drzewo robocze plikiem wymagającym commita**. Dziś robią to wyłącznie `init` i `sync`.
  - **Do zmiany w istniejącym:**
    4. **`init`** — pozostaje prawidłowy bez tożsamości użytkownika i tworzy bezpośredni klucz repozytorium jak dziś. Gdy inicjujący wybierze utworzenie/dodanie tożsamości, zapisuje dla niej pierwsze koperty; przejście z obecnego świata do odbiorców nie wymaga ponownego szyfrowania blobów.
    5. **`unlock`** — zachowuje dzisiejsze wejścia (`unlock <plik>`, `--key`, `--key-only`) dla bezpośredniego klucza/keyringu, a dla tożsamości instaluje ją lokalnie. Filtr z lokalną tożsamością sam znajduje pasujące koperty i odszyfrowuje wymagany klucz repozytorium tylko w pamięci.
    6. **`add-user` / `list-users`** — nowe. **Kontrakt `add-user` rozstrzygnięty 2026-08-16:** komenda wymaga repozytorium logicznie **odblokowanego**, ale nie wymaga klucza repozytorium zapisanego lokalnie na dysku. Dopuszczalne są oba materiały odblokowujące: bezpośredni keyring repozytorium albo prywatna tożsamość, która otwiera własną wersjonowaną kopertę. W drugim wariancie `add-user` odzyskuje właściwy klucz repozytorium wyłącznie w pamięci, pieczętuje go dla klucza publicznego nowego odbiorcy i zapisuje tylko nową kopertę; jawny klucz nie trafia do `.git/`, drzewa roboczego ani na `stdout`. Bez żadnego lokalnego materiału zdolnego otworzyć istniejący klucz komenda odmawia — koperty jednego odbiorcy nie da się przekształcić w kopertę drugiego bez uprzedniego odszyfrowania klucza repozytorium.
    7. **`status`** — nowa luka konfiguracji, niewykrywalna inaczej: **koperta zapisana lokalnie, ale nigdy niezacommitowana**. Odbiorca jej nie zobaczy, repozytorium nie otworzy i nic mu tego nie powie. Ta sama klasa co istniejące „nieskomitowany plik bootstrapowy", więc wpasowuje się w mechanizm, który już jest.
    8. **Komunikat odmowy `init`** — dziś przy braku klucza i śladach wcześniejszej konfiguracji kieruje do `unlock <plik-klucza>`; w klonie z kopertą właściwą radą jest zwykłe `unlock`.
  - **Konsekwencja dla `lock` i `export-key`.** `lock` usuwa lokalny materiał odblokowujący; gdy był nim klucz użytkownika, nie usuwa jego kopii źródłowej poza repo, więc późniejszy `unlock` może znów otworzyć koperty. `export-key` nie jest kontrolą uprawnień: użytkownik mający lokalny klucz repozytorium albo tożsamość zdolną otworzyć jego kopertę może wyprowadzić każdy dostępny mu klucz. Można ograniczać wygodę komendy, lecz nie stanowi to granicy bezpieczeństwa.
  - **Kolejność:** S-10 najpierw ustala keyring, `key_id`, rozpoznanie materiału i `lock`; następnie S-09 dodaje tożsamość, koperty, `unlock` i `add-user`. Dokumentacja oraz testy scenariuszowe domykają oba światy jednym ruchem.
- **Unknowns:**
  - ~~**Format koperty: `age` czy `crypto_box`?**~~ **Rozstrzygnięte 2026-08-11: `crypto_box`** (`zalozenia.md` §Otwarte decyzje poz. 1). Zapisany wcześniej koszt — „każe napisać własny format koperty" — okazał się za ostry: crate implementuje `crypto_box_seal` z libsodium, więc **konstrukcja kryptograficzna jest jego**, a nasze zostaje ułożenie pliku wokół niej, ta sama klasa co `crypto/keyfile.rs`. Twarda reguła „wyłącznie RustCrypto" zostaje więc nienaruszona i to przechyliło szalę przeciw `age`. Przyjęty koszt: koperty nie odczyta żadne cudze narzędzie. Do wykonania: `features = ["seal"]`, bo nie ma go w domyślnych. — Właściciel: użytkownik. Blokuje: **już nie**.
  - **`sequoia-openpgp` odpada na licencji, i to jest fakt zmierzony 2026-08-11, którego `zalozenia.md` poz. 1 nie zna.** Wersja 2.4.1 jest na **LGPL-2.0-or-later**, a lista dozwolonych w `deny.toml` nie zawiera żadnego GPL ani LGPL — polityka istnieje właśnie po to, żeby copyleft nie wszedł bocznymi drzwiami z zależnością i nie unieważnił wyboru `MIT OR Apache-2.0`. Czyli odrzuciłoby ją własne CI, zanim ktokolwiek zmierzyłby zapowiadany „nakład i rozmiar binarki". Wraca do gry tylko wtedy, gdy właściciel świadomie otworzy politykę licencyjną. — Właściciel: użytkownik. Blokuje: nie (zawęża wybór do dwóch).
  - **Jak użytkownik tworzy i przenosi tożsamość?** **Częściowo rozstrzygnięte 2026-08-16:** tworzy ją osobna komenda `identity generate <LABEL> <DIRECTORY>`, która zapisuje prywatny i publiczny plik w podanym katalogu. Rozstrzygnięte jest też miejsce instalacji: prywatna część żyje pod `.git/git-xcrypt/keys/` konkretnego repozytorium i `lock` ją usuwa. Do rozstrzygnięcia w planie pozostają zamrożony format i rozszerzenia obu plików, zachowanie wobec nieistniejącego katalogu oraz dokładny przepływ instalacji przez `unlock`. Transport nadal jest obowiązkiem użytkownika; użycie istniejącego klucza SSH pozostaje poza zakresem, bo jego przeliczenie byłoby własną konstrukcją z prymitywów.
  - **Czy `add-user` / `list-users` to właściwy zestaw komend**, skoro nazwy pochodzą z `git-crypt`, a zasada projektu mówi „pozostałe komendy mają odpowiadać projektom źródłowym co do nazwy i zachowania". — Właściciel: użytkownik. Blokuje: nie.
- **Dwie własności do udokumentowania, obie sprzeczne z intuicją:** dodanie odbiorcy daje dostęp do **całej historii**, gdy otrzyma koperty wszystkich kluczy keyringu; usunięcie odbiorcy **nie odbiera** dostępu do tego, co już sklonował, a rotacja do przodu odcina wyłącznie przyszłe sekrety. Jedno i drugie musi stać w dokumentacji użytkownika, zanim ktokolwiek na tym polegnie.
- **Risk:** to jedyny element roadmapy, który zmienia **model produktu**, a nie dodaje do niego funkcję — persona z PRD to jeden deweloper na kilku maszynach, więc odbiorcy są raczej innym produktem zbudowanym na tym samym formacie niż brakującą częścią tego. Ryzyko drugie, tańsze do przeoczenia: koperta jest miejscem, w którym łatwo złożyć własną konstrukcję kryptograficzną, a to jest dokładnie ta klasa błędu, przed którą broni reguła „nigdy nie składamy konstrukcji z prymitywów". Wybór `crypto_box` czyni to ryzyko realnym i wymagałby zapisania go tak samo jawnie, jak zapisano ryzyko nieaudytowanego `aes-siv`.
- **Status:** todo

### S-10: Rotacja klucza do przodu

> **Current contract — 2026-08-17.** Ten blok zastępuje wcześniejsze szczegóły implementacyjne poniżej, jeśli są z nim sprzeczne. S-10 nie zależy implementacyjnie od S-09: najpierw powstaje neutralny multi-key core i provider bezpośredniego keyringu, dopiero S-09 dodaje provider identity/kopert.

- **Outcome:** użytkownik może przejść na nowy aktywny klucz bez zmiany istniejących obiektów Git; każdy blob jest odszyfrowywany wyłącznie kluczem wskazanym przez własny `key_id`, a brak tego klucza jest błędem.
- **Scope:** keyring jest kolekcją indeksowaną pełnym fingerprintem z mapą blobowego `key_id`; kolizja `key_id` powoduje odmowę. Kanoniczny manifest określa dokładnie jeden `active_key_id`, a local runtime state wiąże go z manifest digest i `generation`.
- **Transaction:** `rotate-key` przechodzi `idle → preparing → prepared → active`. Zanim nowy klucz stanie się aktywny, istnieje zwalidowany snapshot recipientów i komplet kopert dla zachowanych recipientów. W stanach pending/incomplete clean odmawia szyfrowania, a repo-wide lock obejmuje rotację, roster, `lock`, `unlock` i aktualizację runtime state.
- **Publication:** commit i push nie są transakcją lokalną. `status` raportuje co najmniej prepared/uncommitted/unpublished, aby brak publikacji nie wyglądał jak zdrowa konfiguracja.
- **Security boundary:** rotacja do przodu ogranicza dostęp wyłącznie do przyszłych ciphertextów; nie odbiera dostępu do historii, starych klonów ani wcześniej poznanych sekretów.
- **Status:** todo.

- **Outcome:** użytkownik tworzy nowy aktywny klucz repozytorium bez zmiany istniejących obiektów Git. Nowe i ponownie zapisane sekrety są szyfrowane nowym kluczem; stare bloby pozostają czytelne dotychczasowymi kluczami.
- **Change ID:** forward-key-rotation
- **Prerequisites:** S-03 (zrobiony)
- **Parallel with:** —
- **Scope:** lokalny magazyn pod `.git/git-xcrypt/keys/` przechowuje **jeden rozpoznawalny, wersjonowany materiał odblokowujący**: albo bezpośredni klucz/keyring repozytorium (pełna zgodność z v0.1), albo prywatną tożsamość użytkownika. `rotate-key` dodaje nowy aktywny klucz do logicznego keyringu; `clean` szyfruje kluczem aktywnym, a `smudge`, `diff`, `status`, `lock`, `export-key` i `unlock` wybierają klucz po `key_id`. Przy tożsamości użytkownika filtr odczytuje właściwą kopertę z wersjonowanego `.git-xcrypt-keys/`, odszyfrowuje klucz repozytorium wyłącznie w pamięci procesu i nigdy nie zapisuje go lokalnie. Niezmieniony blob nadal może wskazywać na stary klucz także w commicie po rotacji — to poprawne i celowe.
- **Kontrakt struktur danych — rozstrzygnięty 2026-08-16.** Wszystkie nowe formaty i typy S-10 oraz późniejszego S-09 od pierwszej wersji modelują **kolekcję kluczy indeksowaną pełnym `key_id`**, nigdy pojedynczy „bieżący klucz” z miejscem na późniejsze rozszerzenie. Keyring przechowuje każdy nadal potrzebny klucz repozytorium oraz dokładnie jedno wskazanie klucza aktywnego. Rotacja dopisuje nowy klucz i przenosi wskazanie aktywnego, ale nie usuwa poprzedniego. Zaszyfrowany blob zachowuje własny `key_id`: zapis po rotacji używa klucza aktywnego, odczyt starego bloba wybiera stary klucz, a odczyt nowego — nowy. Przy tożsamościach użytkowników wersjonowany magazyn zawiera osobną kopertę dla każdej pary `(identity_id, key_id)`, do której odbiorca ma dostęp; otwarcie repozytorium buduje w pamięci ten sam logiczny keyring z wielu kopert. Brak klucza wskazanego przez blob jest błędem „brak wymaganego klucza”, nigdy próbą użycia aktywnego klucza zastępczo.
- **Granica S-11.** Dopiero udane przepisanie całej oficjalnej historii przez S-11 może sprawić, że stary klucz przestanie być potrzebny w nowym oficjalnym keyringu: każdy osiągalny blob musi wtedy wskazywać nowy `key_id`, zanim stary wpis i jego koperty wolno usunąć. Nie unieważnia to starego klucza kryptograficznie i nie odbiera nim dostępu do starych klonów, forków ani backupów.
- **Lock invariant:** `lock` usuwa z `.git/git-xcrypt/keys/` oba dopuszczalne rodzaje materiału. Sama koperta w drzewie roboczym nie wystarcza wtedy do odszyfrowania checkoutu, więc zachowuje się obecna obietnica zamkniętego repozytorium.
- **Format invariant:** format materiału użytkownika i format klucza repozytorium mają odrębne magic, wersje i parsery; materiał jednego rodzaju nigdy nie może zostać zaakceptowany jako drugi.
- **History invariant:** `rotate-key` działa wyłącznie na pełnej, czytelnej lokalnej historii. Przed wygenerowaniem klucza zbiera `key_id` ze wszystkich zaszyfrowanych blobów osiągalnych z lokalnych refów — bez odszyfrowywania ich treści — i odrzuca kandydata, którego ID już występuje; różny materiał pod tym samym ID nie może wejść do keyringu. Płytki klon, brakujący lub nieczytelny obiekt, nierozwiązywalny ref albo każdy inny stan „nie mogłem sprawdzić historii” powoduje odmowę rotacji, nigdy założenie braku kolizji. Historia nieobecna w lokalnym repozytorium pozostaje poza dowodem, więc komendę wykonuje się po pełnym fetchu na repozytorium, które ma być źródłem oficjalnej historii.
- **Security boundary:** to **nie** odbiera nikomu dostępu do starej historii ani do sekretów, które już odszyfrował. Osoba mająca tylko stary klucz nie odszyfruje sekretów zapisanych po rotacji, lecz nadal odczyta wszystkie bloby szyfrowane starym kluczem. Przy podejrzeniu wycieku trzeba także zmienić rzeczywiste tokeny, hasła i klucze API.
- **Why before S-09:** S-10 ustala wspólną ścieżkę odblokowania — bezpośredni klucz albo lokalna tożsamość otwierająca koperty — oraz semantykę wielu `key_id`. S-09 dodaje dopiero tworzenie tożsamości i zarządzanie odbiorcami/kopertami dla każdego klucza.
- **Non-goal:** nie przepisuje historii i nie wykonuje force-pusha; to osobny `S-11`.
- **Status:** todo

### S-11: Rotacja klucza z przepisaniem historii

> **Current contract — 2026-08-17.** S-11 jest osobnym, późniejszym workflow po S-10, a nie końcowym krokiem zwykłej rotacji. Nie może usuwać starego keyringu ani kopert przed potwierdzoną publikacją i weryfikacją objętych refów.

- **Scope:** wymaga jawnego authoritative remote i ref scope, pełnego mirror-like fetchu reklamowanych branchy i tagów, snapshotu refów, odmowy dla shallow/partial/promisor/replace/grafts oraz każdego nieczytelnego stanu poza jawnie wyłączonym zakresem.
- **Publication:** używa atomic push, jeśli serwer go wspiera; w przeciwnym razie `--force-with-lease` względem snapshotu dla każdego refa, a potem ponownego `ls-remote`/fetchu i skanu. Częściowa porażka zachowuje stare klucze i koperty dla recovery.
- **Security boundary:** wynik to wyłącznie nowa oficjalna historia. Nie jest kryptograficznym revoke dla klonów, forków, cache hostingu ani backupów; rzeczywiste sekrety nadal wymagają osobnej rotacji.
- **Status:** todo i zablokowane do czasu decyzji o authoritative remote/ref scope oraz okresie utrzymania recovery copy.

- **Outcome:** administrator tworzy nowy, oficjalny stan repozytorium, w którym wszystkie objęte deklaracją bloby w historii zostały ponownie zaszyfrowane nowym kluczem, a zdalne refy są zastąpione force-pushem.
- **Change ID:** rewrite-history-key-rotation
- **Prerequisites:** S-10
- **Parallel with:** —
- **Scope:** awaryjna, jawnie destrukcyjna operacja przechodzi po osiągalnej historii, odszyfrowuje stare bloby właściwym kluczem z keyringu, szyfruje je nowym kluczem i buduje od nowa drzewa, commity, tagi oraz refy. Na końcu publikuje wynik force-pushem wyłącznie po wyraźnym potwierdzeniu użytkownika.
- **Operational consequence:** zmienia identyfikatory commitów wszystkich potomków zmienionego obiektu, unieważnia podpisy commitów i tagów oraz wymaga od współpracowników ponownego klonowania lub ręcznej migracji ich gałęzi. Nie jest zwykłym sposobem zmiany klucza.
- **Security boundary:** nie usuwa starego ciphertextu ani starego klucza z istniejących klonów, forków, cache'ów hostingu i backupów; nie zastępuje rotacji rzeczywistych sekretów. Ogranicza wyłącznie oficjalnie publikowaną historię po operacji.
- **Status:** todo

## Completed

| ID | Change ID | Outcome | Completed |
| -- | --------- | ------- | --------- |
| F-01 | git-integration-test-harness | Harness testów na prawdziwych repozytoriach Git | 2026-08-04 |
| S-01 | transparent-encrypt-decrypt | Przezroczyste szyfrowanie i odszyfrowywanie | 2026-08-04 |
| S-02 | gitignore-style-config | Deklaracje w składni `.gitignore` | 2026-08-04 |
| S-03 | key-export-and-unlock | Eksport klucza i odblokowanie po klonie | 2026-08-04 |
| S-04 | lock-repository | Bezpieczne zamykanie repozytorium | 2026-08-04 |
| S-05 | decrypted-diff | Różnice na plaintext | 2026-08-04 |
| S-06 | encryption-status-check | Skan konfiguracji i historii przez `status` | 2026-08-04 |
| S-08 | binary-detection-parity | Zgodność wykrywania plików binarnych z Gitem | 2026-08-04 |
| S-07 | cross-platform-binaries | Wydanie binarek wieloplatformowych (`v0.1.0`) | 2026-08-07 |

## Open Roadmap Questions

1. ~~**Jak nie dopuścić do rozjazdu pliku konfiguracyjnego i konfiguracji czytanej przez gita?**~~ Rozstrzygnięte 2026-08-04: konstrukcja catch-all, `.git-xcrypt` jedynym źródłem prawdy, filtr długożyjący jako warunek wykonalności. Patrz `prd.md` §Open Questions poz. 1 i `zalozenia.md` §Integracja z git. — Właściciel: użytkownik. Blokuje: nic.
2. ~~**Co chroni przed zamknięciem repozytorium bez wcześniejszego wyeksportowania klucza?**~~ Rozstrzygnięte 2026-08-04: potwierdzenie interaktywne, ostrzeżenie z `key_id` zamiast klucza, odmowa przy brudnym katalogu roboczym. — Właściciel: użytkownik. Blokuje: nic.
3. ~~**Jak głęboko `status` sprawdza repozytorium — bieżący stan czy cała historia?**~~ Rozstrzygnięte 2026-08-04: cała osiągalna historia, plus `--fix` na naprawę bezpieczną i kod wyjścia `5` przy znalezisku. — Właściciel: użytkownik. Blokuje: nic.
4. ~~**Jaka nazwa crate'a i binarki wobec kolizji z oryginalnym `git-crypt`?**~~ Rozstrzygnięte 2026-08-04: `git-xcrypt` dla crate'a i binarki. — Właściciel: użytkownik. Blokuje: nic.
5. ~~**Jaka licencja projektu wobec GPL-3.0 projektów inspirujących?**~~ Rozstrzygnięte 2026-08-04: `MIT OR Apache-2.0` dla crate'a i binarki. — Właściciel: użytkownik. Blokuje: nic.
6. **Co chroni użytkownika przed utratą jedynego pliku klucza?** — **zakres rozstrzygnięty 2026-08-04, pytanie zostaje otwarte na przyszłość.** W v0.1 mechanizmu kopii zapasowej nie ma i nie będzie: obowiązek leży po stronie użytkownika, a rozwiązaniem jest dokumentacja — sekcja „The key file is the only copy — back it up yourself" w `README.md` plus wpis w §Known limitations. Przypomnienie w `init` rozważone i odrzucone. Zaimplementowane zabezpieczenia (`export-key` z komunikatem i odmową zapisu w repozytorium, `lock` z potwierdzeniem `yes`, `key_id`, odmową przy niezacommitowanych zmianach i przy innych worktree) zostają opisane jako progi zwalniające, nie jako kopia. Patrz `prd.md` §Open Questions poz. 2. — Owner: użytkownik. Blokuje: nic.
7. ~~**Jaki jest liczbowy próg dla wymagania wydajnościowego?**~~ **Rozstrzygnięte 2026-08-06:** trzy budżety — **25 µs** na plik przepuszczany, **30 µs** na plik szyfrowany, **2 ns/bajt** na szyfr, mierzone jako minimum z 5 przebiegów. Egzekwuje `tests/performance.rs`, świadomie `#[ignore]` (liczby mają sens tylko w `--release`, a zmierzony rozrzut 11% zrobiłby z tego migotliwą bramkę CI). Zapis i uzasadnienie: `prd.md` §Non-Functional Requirements oraz §Open Questions poz. 5. — Właściciel: użytkownik. Blokuje: nic.
8. **Czy któreś wymaganie ma być opcjonalne zamiast koniecznego?** — **odłożone świadomie 2026-08-06: pomijamy.** Wszystkie 11 dostarczone, więc zmiana priorytetu nie zdjęłaby pracy; zostaje zastrzeżenie, że `must-have` odziedziczono po braku odpowiedzi. Patrz `prd.md` §Open Questions poz. 6. — Właściciel: użytkownik. Blokuje: nic.
9. ~~**Czy wiele kluczy w jednym repozytorium i rotacja klucza są poza zakresem?**~~ Rozstrzygnięte — oba są wymienione w `zalozenia.md` §Zakres MVP / poza zakresem jako **poza zakresem v0.1** („Wiele niezależnych kluczy w jednym repo (`--key-name`)" oraz „Rotacja klucza i wycofywanie dostępu odbiorcy z przepisaniem historii"). Format pliku jest na oba gotowy przez `key_id`. — Właściciel: użytkownik. Blokuje: nic.
10. **Czy pozostałe wymagania dostaną własne historyjki użytkownika?** — **odłożone świadomie 2026-08-06: nie dostaną.** Luka w zapisie, nie w pokryciu — kryteria akceptacji żyją jako scenariusze i są bogatsze niż byłyby historyjki. Patrz `prd.md` §Open Questions poz. 8. — Właściciel: użytkownik. Blokuje: nic.
11. **Gdzie i jak private identity jest chroniona na każdej wspieranej platformie?** — **otwarte od 2026-08-17.** Kierunek to globalny magazyn użytkownika, agent/provider albo systemowy keystore; fallback plikowy wymaga jawnego ostrzeżenia i raportu o rzeczywistej ochronie. Bez decyzji o natywnym ACL/keystore S-09 nie deklaruje pełnego wsparcia Windows. Patrz `krytyka.md` §`Proposed Operating Model and File Layout`. — Właściciel: użytkownik. Blokuje: S-09.
12. **Jaki remote i ref scope są autorytatywne dla S-11 oraz jak długo utrzymywać recovery copy starego keyringu?** — **otwarte od 2026-08-17.** Od tej decyzji zależą snapshot refów, force-with-lease, weryfikacja publikacji i bezpieczne usunięcie starego materiału. — Właściciel: użytkownik. Blokuje: S-11.

## Parked

- **Zarządzanie odbiorcami i praca zespołowa** — **przeniesione 2026-08-11 do `S-09`**, więc nie leży już tutaj. Powodem zaparkowania było PRD §Non-Goals, i ten zapis zostaje w mocy **dla v0.1**; `S-09` stoi poza nią.
- **Kompatybilność z repozytoriami oryginalnego git-crypt** — Dlaczego: PRD §Non-Goals; własny format bez ścieżki migracji.
- **Ukrywanie metadanych** — Dlaczego: PRD §Non-Goals; nazwy plików, rozmiary i fakt zmiany pozostają jawne z założenia konstrukcji.
- **Ochrona przed skompromitowaną maszyną** — Dlaczego: PRD §Non-Goals; po odblokowaniu sekrety leżą jawnie na dysku.
- **Buforowanie dyskowe dla wielkich plików** — Dlaczego: odłożone świadomie 2026-08-06 (`zalozenia.md` §Otwarte decyzje poz. 5). Dziś każdy plik trafia do RAM w całości, a szczyt zależy od kierunku — zmierzone 2026-08-12 na 128 MB: **deszyfrowanie 2,03×, szyfrowanie 3,03×**. Wcześniejszy zapis „~2× jego rozmiar" opisywał wyłącznie deszyfrowanie. Zmierzono też najtańsze wyjście, gdyby temat wrócił: `encrypt_in_place` z buforem wymiarowanym raz schodzi do **1,03×**, bez zmiany formatu i bez trybu blokowego, kosztem przejęcia własności plaintextu przez `cipher::encrypt`. Odłożenie nic nie zamraża: obie drogi wyjścia (buforowanie na dysku, nowy `suite` z trybem blokowym) mieszczą się w zamrożonym formacie, więc powrót do tematu nie kosztuje więcej później niż dziś. Wraca przy pierwszym zgłoszeniu OOM albo przy decyzji o wspieraniu plików rzędu gigabajta; produkt celuje dziś w pliki konfiguracyjne rzędu kilobajtów.
- **Natywne czyszczenie historii (`purge-history`)** — Dlaczego: rozstrzygnięte 2026-08-04. Własny odpowiednik `git-filter-repo` w Ruście to element wielkości `S-01` (wywołanie zewnętrznego narzędzia odpada przez wymóg samowystarczalnej binarki), a operacja i tak nie cofa wycieku — sekret zostaje w forkach, cache'ach i cudzych klonach. W v0.1 `S-06` raportuje ekspozycję i wypisuje procedurę zaczynającą się od rotacji sekretu.
