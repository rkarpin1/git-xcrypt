# Critique: Per-user Keys and Rotation

## Purpose

Ten dokument jest krytycznym przeglądem S-09 w kontekście S-10 i S-11. Nie stanowi planu implementacji ani zatwierdzonego projektu struktur danych. Jego zadaniem jest utrzymać widoczne problemy, które trzeba rozstrzygnąć przed planowaniem, oraz rekomendacje, które należy próbować obalić przed ich przyjęciem.

Priorytety, w tej kolejności:

1. wygoda użytkownika bez fałszywych obietnic;
2. bezpieczeństwo i odtwarzalność repozytorium;
3. bezpieczeństwo kluczy i tożsamości.

## Summary

Obecny szkic S-09 poprawnie opisuje podstawowy mechanizm dystrybucji: klucz repozytorium zostaje zapieczętowany osobno dla każdego odbiorcy, a prywatna tożsamość otwiera właściwe koperty. To jednak nie jest jeszcze kompletny system zarządzania dostępem.

Najważniejsze odrzucone założenia:

- koperty z bieżącego worktree nie mogą być jedynym źródłem kluczy dla filtra;
- posiadanie klucza nie tworzy automatycznie bezpiecznej roli administratora;
- `rotate-key` nie jest pojedynczym atomowym zapisem;
- `remove-user` nie odbiera dostępu do starych kluczy ani kopert;
- lokalny skan nie dowodzi kompletności całej historii zdalnej;
- dwuplikowa tożsamość nie powstaje atomowo tylko dlatego, że każdy plik zapisano atomowo;
- skopiowanie prywatnej identity do każdego `.git/` nie jest niewinnym odpowiednikiem dzisiejszego klucza repozytorium — jedna identity może otwierać wiele repozytoriów.

S-09 nie powinno wejść do planowania implementacji, dopóki nie zostaną rozstrzygnięte: model delegowania dostępu, manifest i `active_key_id`, źródło runtime keyringu, protokół rotacji, semantyka dodawania i usuwania odbiorcy, zakres S-11 oraz sposób przechowywania prywatnej identity.

## Desired Invariants

Każda przyszła propozycja powinna być oceniana względem następujących własności:

- blob jest odszyfrowywany wyłącznie kluczem wskazanym przez jego `key_id`;
- rotacja dodaje nowy klucz i nie usuwa poprzednich kluczy potrzebnych historii;
- dokładnie jeden klucz jest aktywny do nowych zapisów;
- brak właściwego klucza kończy operację błędem, bez próby użycia klucza aktywnego zastępczo;
- nowy ciphertext nie może powstać, dopóki repozytorium nie ma kompletnej drogi odzyskania jego klucza;
- awaria, konflikt albo brak możliwości sprawdzenia nie mogą wyglądać jak poprawna konfiguracja;
- prywatny klucz użytkownika i jawny keyring nigdy nie trafiają do wersjonowanej części repozytorium;
- operacja opisywana jako usunięcie lub rotacja nie może obiecywać cofnięcia dostępu do danych już skopiowanych;
- S-11 nie usuwa starego klucza przed zakończeniem i weryfikacją publikacji wszystkich objętych refów.

## Checkout and Runtime Key Source

### Problem

Szkic zakłada, że filtr z lokalną prywatną identity odczyta koperty z wersjonowanego `.git-xcrypt-keys/` i odzyska klucze wyłącznie w pamięci. To uzależnia odszyfrowanie od zawartości bieżącego worktree.

Git nie gwarantuje kolejności, w której podczas checkoutu zapisze koperty i pliki szyfrowane. Filtr może otrzymać blob wskazujący nowy `key_id`, kiedy worktree nadal zawiera koperty ze starego commita. Długowieczny proces może dodatkowo trzymać cache z poprzedniej gałęzi.

Problem obejmuje także:

- `git checkout` między commitami o różnych generacjach kluczy;
- `git show <ref>:<path>` i diff między refami;
- detached HEAD i historyczne checkouty;
- merge, w którym manifest, koperty i ciphertext pochodzą z różnych stron;
- linked worktrees współdzielące Git common dir, ale mające inne checkouty.

### Consequence

Poprawny commit może być nieodtwarzalny tylko dlatego, że Git wybrał niekorzystną kolejność aktualizacji. Jest to błąd dostępności danych, nie drobna niedogodność. Próba naprawy przez ponowienie checkoutu byłaby nieakceptowalnym, niedeterministycznym UX.

### Recommendation

Worktree nie może być jedynym autorytatywnym źródłem runtime. Należy rozważyć dwa kierunki:

1. atomowy lokalny runtime keyring w Git common dir, związany z konkretną wersją manifestu;
2. rozwiązywanie kopert z dokładnego drzewa Git odpowiadającego przetwarzanemu stanowi.

Drugi wariant jest trudny, ponieważ protokół filtra nie przekazuje docelowego commit ID. Pierwszy poprawia UX, ale może wymagać zapisania odszyfrowanych kluczy na dysku, co przeczy decyzji „z kopert tylko do RAM”. Ten konflikt jest blockerem i wymaga jawnej decyzji, nie optymalizacji implementacyjnej.

Cache nie może być unieważniany wyłącznie przez mtime. Powinien być związany z digestem kanonicznego manifestu, generacją i `identity_id`, a każda niezgodność musi wymuszać ponowną walidację albo odmowę.

## Active Key Authority

### Problem

Keyring ma przechowywać wiele kluczy i dokładnie jedno wskazanie aktywnego klucza, ale nie ustalono, gdzie to wskazanie jest autorytatywne.

Jeżeli `active_key_id` jest tylko lokalne, dwa klony mogą po rotacji nadal szyfrować różnymi kluczami. Jeżeli jest wyłącznie wersjonowane, checkout starego commita albo rollback gałęzi może ponownie wybrać klucz historyczny do nowych zapisów.

### Consequence

Repozytorium może równolegle produkować nowe bloby pod A i B, choć operatorzy wierzą, że rotacja już się zakończyła. Użytkownik usunięty przed rotacją może dostać dalszy dostęp, jeśli ktoś nieświadomie zapisze nowy sekret starym kluczem.

### Recommendation

Potrzebny jest wersjonowany, kanoniczny manifest zawierający co najmniej:

- stabilne `repo_id`;
- monotoniczną `generation`;
- `active_key_id`;
- pełne fingerprinty kluczy wymaganych przez oficjalną historię;
- roster odbiorców albo jednoznaczne odniesienie do jego stanu;
- wersję formatu i digest całej treści.

Lokalny writer przed clean powinien sprawdzić, że zna aktywny klucz z oczekiwanego manifestu i że repozytorium nie jest w stanie pending/incomplete. Historyczny lub detached checkout powinien być domyślnie tylko do odczytu w zakresie szyfrowanych ścieżek albo wymagać jawnego potwierdzenia przed tworzeniem nowego ciphertextu starym kluczem.

## Rotation Transaction

### Problem

S-10 wymaga zmiany kilku niezależnych miejsc:

- lokalnego keyringu;
- aktywnego klucza;
- manifestu;
- koperty nowego klucza dla każdego zachowanego odbiorcy;
- worktree i indeksu;
- commita oraz późniejszego pushu.

Git nie zapewnia transakcji łączącej `.git/`, pliki wersjonowane, indeks, commit i zdalne repozytorium. Atomowy zapis pojedynczego pliku nie rozwiązuje tego problemu.

### Failure Scenarios

- B zapisano do lokalnego keyringu, ale proces padł przed utworzeniem kopert;
- część kopert B istnieje, część nie;
- manifest wskazuje B, ale koperty nie zostały dodane do indeksu;
- commit zawiera nowe bloby B, ale nie zawiera wszystkich kopert B;
- push bloba i manifestu dotarł, ale commit przyznający odbiorcom koperty nie dotarł;
- drugi proces `git add` uruchomił clean podczas przygotowywania rotacji;
- dwa worktree lub dwa klony przeprowadziły konkurencyjne rotacje.

### Recommendation

`rotate-key` powinno mieć jawny state machine, np.:

```text
idle → preparing → prepared → active
          ↓            ↓
       rollback      resume
```

Najpierw powstaje zamrożony snapshot odbiorców, nowy klucz i kompletny zestaw kopert. Następnie cały przygotowany stan jest walidowany. Dopiero później nowy klucz może zostać aktywny do clean.

W Git common dir powinien istnieć repo-wide lock współdzielony przez rotację, `add-user`, `remove-user`, `lock`, `unlock` oraz operacje aktualizujące runtime keyring. Filtr musi odmawiać szyfrowania w stanie pending/incomplete. Przerwana operacja musi dawać jednoznaczne `resume` albo bezpieczny `rollback` bez zgadywania.

Nie da się uczynić commita i pushu częścią lokalnej transakcji. CLI musi więc pozostawić jawny stan „przygotowane lokalnie, nieopublikowane”, a `status` powinien oznaczać go jako lukę konfiguracji.

## Membership and Authorization

### Problem

Posiadacz klucza repozytorium może:

- odszyfrować dane;
- utworzyć kopertę dla dowolnego nowego odbiorcy;
- wyeksportować keyring;
- przekazać plaintext klucza poza programem.

To oznacza, że zdolność odczytu jest w praktyce zdolnością delegowania. Sealed box mówi tylko „ten klucz prywatny może otworzyć kopertę”; nie mówi „kto legalnie nadał dostęp”. Git ACL i review chronią oficjalną gałąź, ale nie blokują prywatnego przekazania klucza.

### Consequence

Nazwy `add-user`, `remove-user` i `list-users` mogą sugerować system ACL silniejszy niż rzeczywistość. Użytkownik może błędnie uznać, że tylko administrator potrafi nadać dostęp albo że usunięcie wpisu odbiera dostęp kryptograficznie.

### Recommendation

Trzeba wybrać jeden z dwóch modeli:

1. **Capability model:** każdy posiadacz klucza może delegować. Narzędzie nazywa odbiorców, nie użytkowników/role, i jawnie dokumentuje brak kryptograficznego administratora.
2. **Administrative policy:** podpisany manifest określa, kto może publikować oficjalne zmiany rosteru. Nadal nie zapobiega ręcznemu przekazaniu klucza, lecz pozwala zweryfikować autentyczność oficjalnego członkostwa i audytować zmiany.

Nie wolno wybierać drugiego modelu tylko po to, aby stworzyć pozór odwoływalności. Podpisany roster chroni integralność procesu administracyjnego, nie kontroluje osoby, która już poznała plaintext klucza.

## Manifest Authenticity and Rollback

### Problem

Wersjonowany roster może zostać cofnięty przez checkout, revert, merge albo złośliwy commit. `crypto_box` nie uwierzytelnia autora koperty. Przywrócenie starego odbiorcy przed kolejną rotacją może spowodować wygenerowanie dla niego koperty nowego klucza.

### Recommendation

Jeżeli projekt przyjmie administracyjną politykę, manifest powinien być kanoniczny, podpisany i monotoniczny. Rotacja nie powinna bezwarunkowo ufać rosterowi z worktree; powinna pokazać dokładny zestaw odbiorców, porównać generation z lokalnie zaakceptowanym stanem i odmówić niejawnego rollbacku.

Jeżeli projekt pozostanie przy capability model, rollback musi nadal być wykrywany operacyjnie. Minimalny kontrakt to jawne potwierdzenie snapshotu odbiorców podczas rotacji i raportowanie przez `status`, że generation cofnęła się względem ostatnio zaakceptowanego lokalnego stanu.

## Add Recipient Semantics

### Problem

Przy wielu kluczach repozytorium `add-user` nie ma jednego oczywistego znaczenia. Może utworzyć koperty:

- dla wszystkich kluczy historycznych i aktywnego;
- tylko dla aktywnego klucza;
- dla wybranego zakresu.

Pierwszy wariant ujawnia całą historię. Drugi daje dostęp tylko do przyszłych lub ponownie zapisanych blobów i łamie historyczny checkout. Trzeci jest elastyczny, ale łatwo tworzy użytkownika, który wygląda na dodanego, lecz nie potrafi otworzyć części repozytorium.

### Recommendation

Najbezpieczniejszy UX dla podstawowego przepływu to domyślne przyznanie wszystkich kluczy wymaganych przez oficjalną historię, z wyraźnym komunikatem przed zapisem: nowy odbiorca otrzymuje dostęp do całej dostępnej historii.

Partial grant powinien być oddzielną, jawną funkcją i pokazywać ograniczenie. Odbiorca posiadający tylko część keyringu nie może przyznać innej osobie pozornie pełnego dostępu. `add-user` powinno albo utworzyć komplet, albo odmówić i wymienić brakujące `key_id`.

## Remove Recipient and Revocation

### Problem

Usunięcie koperty z HEAD nie odbiera dostępu do wcześniej wydanego klucza. Koperta nadal znajduje się w historii i może zostać pobrana również przez świeży klon, jeśli odpowiedni commit pozostaje osiągalny. Odbiorca mógł też wcześniej zapisać keyring albo plaintext.

### Recommendation

Operacja powinna być opisana jako usunięcie z bieżącego rosteru, nie cofnięcie dostępu. Odcięcie od przyszłych danych wymaga jednego workflow:

1. usuń odbiorcę z przyszłego rosteru;
2. utwórz nowy aktywny klucz;
3. nie twórz jego koperty dla usuniętego odbiorcy;
4. publikuj nowe dane wyłącznie nowym kluczem.

`remove-user` bez rotacji powinno albo odmówić, albo bardzo wyraźnie powiedzieć, że nie odcina od przyszłych zapisów pod obecnym kluczem. Lepszym UX może być komenda prowadząca cały workflow remove+rotate.

S-11 usuwa historyczne koperty wyłącznie z nowej oficjalnej historii. Nie odbiera dostępu do klonów, forków, cache hostingu ani backupów. Rzeczywiste tokeny, hasła i klucze API muszą być rotowane osobno.

## Envelope Format

### Problem

Zapis `sealed(master key) + identity_id` jest za słaby. Metadane poza ciphertextem można przepiąć między ścieżkami, odbiorcami i repozytoriami. Blobowy `key_id` ma 64 bity i został zaprojektowany jako pole zamrożonego nagłówka, nie jako globalny identyfikator klucza w systemie wielu repozytoriów.

### Recommendation

Payload koperty powinien zawierać i po otwarciu weryfikować:

- magic i wersję;
- domain separator;
- stabilne `repo_id`;
- pełny publiczny `identity_id` odbiorcy;
- pełny fingerprint klucza repozytorium;
- 64-bitowy blobowy `key_id`;
- sam klucz główny.

Nowy keyring powinien indeksować wpisy pełnym fingerprintem i dodatkowo mapować blobowe `key_id`. Jeżeli dwa wpisy mają ten sam blobowy `key_id`, dopasowanie jest niejednoznaczne i operacja musi odmówić.

Parser musi ograniczać liczbę i rozmiar kopert, odrzucać symlinki, duplikaty, niekanoniczne kodowanie i obce wersje. Nazwa pliku ani katalogu nie jest uwierzytelnioną metadaną.

## Identity Storage

### Problem

Kopiowanie prywatnej identity do `.git/` każdego repozytorium tworzy wiele długowiecznych kopii sekretu. Jedna identity może otwierać wiele repozytoriów, więc jej wyciek ma większy promień niż wyciek pojedynczego keyringu repozytorium.

Na Windows obecny zapis owner-only nie zawęża ACL. Plik dziedziczy uprawnienia katalogu. `.git/` nie jest systemowym magazynem sekretów, a cache, backupy IDE, narzędzia diagnostyczne i skanery mogą go kopiować.

### Recommendation

Preferowany kierunek do zbadania:

- jedna źródłowa identity w chronionym globalnym magazynie użytkownika lub systemowym keystore/agent;
- repozytorium przechowuje tylko referencję/identyfikator używanej identity;
- tryb kopiowania do `.git/` jest jawnym fallbackiem z ostrzeżeniem o powstaniu kolejnej kopii;
- `lock` usuwa lokalną capability lub referencję zgodnie z wybranym modelem;
- narzędzie raportuje, jakie zabezpieczenia pliku rzeczywiście zastosowano.

S-09 nie powinno być uznane za bezpieczne na Windows bez jawnej decyzji dotyczącej ACL lub magazynu systemowego. W przeciwnym razie ta sama identity otwierająca wiele repozytoriów może być czytelna dla innych kont zgodnie z odziedziczonym ACL.

## Identity Generation UX

### Problem

Składnia `identity generate <LABEL> <DIRECTORY>` jest czytelna, ale generowanie nazw z label niesie problemy:

- `/`, `\`, `:`, nazwy zastrzeżone Windows i końcowe kropki/spacje;
- kolizje `Robert/Laptop`, `Robert-Laptop` i różnic wielkości liter;
- różne normalizacje Unicode;
- limit długości komponentu ścieżki;
- katalog docelowy będący repozytorium, worktree, symlinkiem lub reparse pointem prowadzącym do repozytorium.

Dwa pliki nie tworzą jednej transakcji. Crash po zapisie private, ale przed public, zostawia stan częściowy. Ogólna odmowa nadpisania może później uniemożliwić bezpieczne dokończenie.

### Recommendation

- label pozostaje metadaną i czytelnym składnikiem nazwy, ale nie selektorem bezpieczeństwa;
- transformacja label do nazwy musi być kanoniczna i jednakowa na wszystkich platformach;
- kolizja po transformacji powoduje odmowę z pokazaniem obu labeli;
- cel przechodzi tę samą ochronę co `export-key`, obejmując wszystkie worktree oraz dowiązania;
- private powstaje pierwszy, public jest deterministycznie odtwarzany z private;
- ponowienie rozpoznaje poprawny istniejący private i bezpiecznie dopisuje brakujący public;
- istniejący private o innej zawartości nigdy nie jest zastępowany niejawnie.

## Export and Irrevocable Copies

### Problem

Dzisiejsze `export-key` eksportuje pojedynczy klucz repozytorium. Po S-10 może wyeksportować cały keyring historyczny, tworząc przenośną, nieodwoływalną capability omijającą system odbiorców.

### Recommendation

Nie należy automatycznie rozszerzać starej semantyki. Eksport keyringu powinien być osobną, jawnie niebezpieczną operacją, wymagającą wskazania zakresu kluczy albo potwierdzenia eksportu całej historii. Komunikat musi powiedzieć, że późniejsze usunięcie odbiorcy, rotacja identity i usunięcie kopert nie odbiorą dostępu posiadaczowi tej kopii.

## CI and Ephemeral Use

### Problem

CI nie powinno zapisywać prywatnej identity w workspace ani trwałym cache. Brak bezplikowego wejścia skłoni użytkowników do argv, zmiennych środowiskowych, artefaktów albo plików pozostających po jobie.

### Recommendation

Potrzebny jest przepływ analogiczny do bezpieczniejszego `unlock --key`, np. identity ze stdin, krótkotrwały agent albo systemowy secret provider. Klucz nie może znaleźć się w argv. Cleanup musi być jawny i testowany również po błędzie oraz przerwaniu procesu.

## Status and List Output

### Problem

Proste `list-users` ukryje częściowy dostęp. Po kilku rotacjach ten sam odbiorca może mieć koperty A i C, ale brak B. Inny może mieć tylko aktywny klucz. Sam napis „user exists” niczego nie dowodzi.

### Recommendation

Raport powinien rozdzielać trzy osie:

1. **Repository integrity:** manifest, generation, active, kompletność i spójność wersjonowanego stanu.
2. **Recipient coverage:** macierz odbiorca × wymagany klucz z wartościami full/partial/missing/revoked-for-future.
3. **Local access:** które wymagane klucze może odzyskać bieżąca identity.

`status` powinien porównywać worktree, indeks i HEAD oraz raportować stan pending/uncommitted/unpushed. Zgodnie z istniejącą zasadą każdy brak możliwości sprawdzenia należy do `undetermined`, nigdy do zdrowego stanu.

Skrócone `identity_id` może służyć interaktywnemu wyborowi tylko przy jednoznacznym dopasowaniu. Przed zmianą narzędzie pokazuje pełne ID i label. Skrypty powinny używać pełnego ID.

## S-11 Publication and Cleanup

### Problem

S-11 ma przepisać wiele refów i force-pushować je na serwer. Serwer może nie obsługiwać atomowego pushu wielu refów, część aktualizacji może się udać, a równoległy push może przywrócić starą historię. Lokalny „pełny fetch” nie obejmuje automatycznie hidden refs, forków, usuniętych refów ani cudzych backupów.

### Recommendation

S-11 wymaga:

- wskazania authoritative remote i dokładnego zakresu refów;
- mirror-like fetch reklamowanych branches i tags;
- odmowy dla shallow, partial, promisor, replace/grafts i każdego nieczytelnego stanu, chyba że jawnie wyłączono go ze scope;
- snapshotu identyfikatorów wszystkich refów przed rewrite;
- maintenance freeze albo atomic push, jeśli serwer go wspiera;
- `--force-with-lease` względem snapshotu dla każdego refa;
- ponownego `ls-remote`/fetch i skanu po publikacji;
- zachowania starego keyringu i kopert przy każdej częściowej porażce;
- osobnego, późniejszego cleanupu po okresie migracji.

Podpisane commity i tagi zostaną unieważnione. Nie wolno przenosić starej sygnatury do nowego obiektu tak, jakby nadal była prawdziwa. Trzeba ją usunąć z raportem albo wymagać ponownego podpisania.

Stary klucz „traci sens” wyłącznie dla nowej oficjalnej historii po potwierdzonym rewrite. Nadal otwiera stare klony, forki, cache i backupy. Nie wolno opisywać S-11 jako kryptograficznego unieważnienia klucza.

## Recommended Data Model

To propozycja do dalszego zakwestionowania, nie zatwierdzony format:

```text
Versioned key manifest
├── format_version
├── repo_id
├── generation
├── active_key_id
├── required_keys[]
│   ├── blob_key_id
│   └── full_key_fingerprint
├── recipients[]
│   ├── identity_id
│   ├── label
│   └── policy/status
└── optional administrator signatures

Versioned envelope
├── format_version
├── repo_id
├── recipient_identity_id
├── blob_key_id
├── full_key_fingerprint
└── sealed payload containing the same bound metadata and master key

Local runtime state in Git common dir
├── manifest_digest
├── generation
├── identity_id or provider reference
├── transaction state
└── key provider/cache according to the unresolved RAM-vs-disk decision
```

Direct keyring oraz identity provider powinny implementować ten sam neutralny model wielu kluczy. S-10 nie powinno zależeć implementacyjnie od S-09: najpierw powstaje multi-key keyring i provider bezpośredni, później S-09 dodaje provider oparty o identity i koperty.

## Recommended Decision Order

1. Ustalić capability model albo osobną administracyjną politykę członkostwa.
2. Ustalić `repo_id`, kanoniczny manifest, generation i autorytet `active_key_id`.
3. Rozwiązać runtime key source niezależny od kolejności checkoutu.
4. Rozstrzygnąć kompromis RAM-only kontra lokalny atomowy cache kluczy.
5. Zaprojektować state machine i recovery dla `rotate-key`.
6. Ustalić domyślny full grant, zasady partial grant i remove+rotate.
7. Zdefiniować macierz oraz werdykty `status` i `list-users`.
8. Rozstrzygnąć globalny magazyn identity, Windows ACL i przepływ CI.
9. Zdefiniować authoritative remote, ref scope i cleanup S-11.
10. Dopiero potem zamrażać formaty, rozszerzenia plików i finalne komendy CLI.

## Open Decisions

1. Czy każdy odbiorca może delegować dostęp, czy oficjalny roster ma osobną administrację?
2. Czy `add-user` domyślnie przyznaje całą oficjalną historię?
3. Czy usunięcie odbiorcy zawsze uruchamia rotację dla przyszłych danych?
4. Gdzie jest autorytatywne `active_key_id` podczas clean i historycznego checkoutu?
5. Czy odszyfrowany runtime keyring może być zapisany w Git common dir?
6. Czy prywatna identity jest globalna, kopiowana per repo, czy obsługiwana przez agent/keystore?
7. Czy S-09 może być wspierane na Windows bez natywnego zawężenia ACL?
8. Jakie refy i jaki remote tworzą oficjalny zakres S-11?
9. Czy roster jest podpisany i monotoniczny, czy każda rotacja ręcznie zatwierdza jego snapshot?
10. Jak długo po S-11 utrzymywana jest recovery copy starego keyringu?

## Evidence

- `context/foundation/roadmap.md` — aktualny kontrakt S-09, S-10 i S-11.
- `context/changes/per-user-keys-review/research.md` — raport źródłowy z trzech niezależnych przeglądów.
- `src/crypto/format.rs` — zamrożony 64-bitowy `key_id` w nagłówku bloba.
- `src/crypto/key.rs` — wyprowadzenie `key_id` z klucza głównego.
- `src/crypto/keyfile.rs` — istniejący standard walidacji i zeroizacji materiału.
- `src/util/atomic.rs` — atomowy zapis pojedynczego pliku oraz ograniczenia uprawnień Windows.
- `src/commands/export_key.rs` — istniejąca ochrona celu eksportu przed trafieniem do worktree.
- `src/commands/status.rs` — zasada fail-closed dla shallow i partial clone.
- `tests/lock_unlock.rs` — linked worktrees oraz wyścigi jako zmierzone granice bezpieczeństwa.
