---
date: 2026-08-16T11:36:46+02:00
researcher: Codex
git_commit: 9924d0c7c714c78fad19ab5ed0c34bff78949181
branch: master
repository: git-xcrypt
topic: "Krytyczna analiza S-09 z uwzględnieniem S-10 i S-11"
tags: [research, per-user-keys, key-rotation, history-rewrite, security, ux]
status: complete
last_updated: 2026-08-16
last_updated_by: Codex
---

# Research: Krytyczna analiza S-09 z uwzględnieniem S-10 i S-11

**Date**: 2026-08-16T11:36:46+02:00
**Researcher**: Codex
**Git Commit**: 9924d0c7c714c78fad19ab5ed0c34bff78949181
**Branch**: master
**Repository**: git-xcrypt

## Research Question

Ponownie przeanalizować S-09, biorąc pod uwagę S-10 i S-11. Aktywnie negować obecne propozycje i wskazać dziury, z priorytetem: wygoda użytkownika, bezpieczeństwo repozytorium, bezpieczeństwo kluczy.

## Summary

Obecny szkic dobrze opisuje **dystrybucję** kluczy repozytorium przez koperty, ale nie opisuje jeszcze bezpiecznego **zarządzania dostępem**. Zdanie roadmapy, że otwarte zostały „jedynie nazwy komend oraz ergonomia”, jest nieprawdziwe. Przed planowaniem S-09 pozostają blokujące decyzje architektoniczne.

Największa luka techniczna: filtr nie może traktować kopert z bieżącego worktree jako jedynego źródła kluczy. Przy checkout między stanami Git może podać smudge blob z nowym `key_id`, zanim zapisze odpowiadającą mu kopertę. Ten sam problem dotyczy innych refów i długowiecznego cache filtra.

Największa luka bezpieczeństwa: nie ma modelu autoryzacji członkostwa. Posiadacz klucza może delegować go poza narzędziem, `export-key` może wyprowadzić cały keyring, a sealed box nie poświadcza autora nadania. Trzeba albo świadomie przyjąć capability model („każdy czytelnik może delegować”), albo zaprojektować osobną, podpisaną politykę administracyjną — ze świadomością, że nie powstrzyma ona ręcznego przekazania plaintextu.

Największa luka operacyjna: `rotate-key` zmienia lokalny keyring, aktywny klucz i wiele wersjonowanych kopert, lecz Git nie daje transakcji obejmującej `.git/`, worktree, indeks, commit i push. Bez jawnego state machine awaria może opublikować ciphertext, którego odbiorcy nie potrafią otworzyć.

## Detailed Findings

### Blockers — nie planować S-09 przed rozstrzygnięciem

1. **KRYTYCZNE — bootstrap kopert zależy od kolejności checkoutu.** S-09 zakłada, że filtr znajduje koperty w `.git-xcrypt-keys/`, a odzyskany klucz istnieje tylko w RAM (`context/foundation/roadmap.md:48`, `:56`, `:77`). Git nie gwarantuje, że nowa koperta pojawi się w worktree przed blobem zaszyfrowanym nowym kluczem. `git show`, diff innych refów i checkout historycznego commita również nie odpowiadają bieżącemu worktree. Potrzebne jest źródło runtime niezależne od kolejności aktualizacji worktree: atomowy cache w common dir albo rozwiązywanie kopert z właściwego drzewa Git. Filtr nie dostaje docelowego commit ID, więc druga droga nie jest oczywista.

2. **KRYTYCZNE — nie wiadomo, gdzie żyje autorytatywne `active_key_id`.** Lokalny active powoduje, że dwa klony mogą pisać A i B po tej samej rotacji. Wersjonowany active podlega rollbackowi i problemowi kolejności checkoutu. Historyczny/detached checkout nie może niejawnie upoważniać do nowych zapisów starym kluczem. Potrzebny jest kanoniczny manifest z generacją oraz reguła walidacji przez clean przed każdym szyfrowaniem.

3. **KRYTYCZNE — rotacja nie jest transakcją.** S-10 musi utworzyć klucz B, koperty B dla odbiorców, zmienić active i przygotować commit (`context/foundation/roadmap.md:77-80`). Crash lub równoległy `git add` może zostawić tylko część tego stanu. Najpierw musi powstać komplet dla zamrożonego snapshotu odbiorców, potem walidacja, a dopiero na końcu aktywacja B. Stan pending/incomplete musi blokować clean i dawać możliwość bezpiecznego resume/rollback; sam późniejszy raport `status` jest za słaby.

4. **KRYTYCZNE — roster nie ma autentyczności ani ochrony przed rollbackiem.** `crypto_box` sealed box zapewnia poufność dla odbiorcy, nie dowodzi kto nadał dostęp. Dowolny commit może przywrócić usuniętego odbiorcę, a przyszła rotacja może na tej podstawie ponownie wydać mu kopertę. Potrzebna jest jawna decyzja: niezaufany roster zatwierdzany przy każdej rotacji albo podpisany, monotoniczny manifest członkostwa.

5. **KRYTYCZNE — S-11 nie ma transakcyjnej publikacji.** Force-push wielu refów może udać się częściowo; równoległy push może odtworzyć starą historię. Wymagane są snapshot refów, maintenance freeze lub atomic push, `--force-with-lease` dla każdego refa i ponowna weryfikacja remote. Porażka na dowolnym etapie zachowuje stare klucze i koperty (`context/foundation/roadmap.md:92-94`).

### Security of repository

6. **WYSOKIE — `add-user` nie definiuje zakresu dostępu.** Przy wielu `key_id` nie wiadomo, czy nadaje całą historię, tylko active, czy podzbiór. Domyślne wszystkie oficjalnie wymagane klucze jest najwygodniejsze, ale ujawnia całą historię. Partial grant musi być jawny; użytkownik mający tylko część keyringu nie może stworzyć pozornie kompletnego grantu.

7. **WYSOKIE — `remove-user` jest mylącą nazwą i operacją.** Usunięcie koperty z HEAD nie odbiera dostępu do kluczy: koperty pozostają w historii, również dla świeżego klona. Odcięcie od przyszłości wymaga usunięcia z bieżącego rosteru **i rotacji**, bez koperty nowego klucza dla usuniętego odbiorcy. Pełne usunięcie historycznych kopert z oficjalnych refów wymaga S-11, ale nadal nie działa na stare klony, forki i backupy.

8. **WYSOKIE — `status` potrzebuje trzech oddzielnych werdyktów.** Musi osobno raportować: integralność manifestu repozytorium; macierz kompletności odbiorca × wymagany `key_id`; lokalny dostęp bieżącej tożsamości. Powinien porównywać worktree, index i HEAD oraz wykrywać wspólne staged/committed zmiany manifestu i kopert. Prosta lista użytkowników i kontrola „koperta niezacommitowana” będą dawały fałszywy spokój.

9. **WYSOKIE — konflikty Git mogą tworzyć syntaktycznie poprawny, semantycznie zły roster.** Równoległe add/remove/rotate mogą zgubić odbiorcę, active albo kopertę. Manifest wymaga kanonicznego formatu, generation/epoch, jednoznacznych duplikatów i walidacji kompletności po merge.

10. **WYSOKIE — obecny 64-bitowy `key_id` nie powinien być globalną tożsamością klucza.** Zamrożony nagłówek ma 8 bajtów (`src/crypto/format.rs:15`, `src/crypto/key.rs:80`). Nowy keyring i koperta powinny mieć dodatkowy pełny, domenowo separowany fingerprint klucza oraz `repo_id`; blobowe 64 bity pozostają indeksem wymagającym jednoznacznego dopasowania.

11. **ŚREDNIE — niezaufane koperty są powierzchnią DoS i substytucji.** Payload koperty powinien po otwarciu wiązać magic/version, domenę, `repo_id`, pełne `identity_id`, pełny fingerprint klucza i blobowy `key_id`. Potrzebne są limity liczby/rozmiaru, zakaz symlinków, kanoniczne kodowanie, reguły duplikatów i fail-closed dla obcych wersji.

### Security of keys

12. **KRYTYCZNE — zdolność odczytu jest dziś równoważna zdolności delegowania.** `add-user` i `export-key` umożliwiają każdemu odbiorcy przekazanie wszystkich dostępnych kluczy (`context/foundation/roadmap.md:59`, `:62`). Role repozytoryjne nie tworzą kryptograficznej granicy. Jeśli projekt pozostaje płaski, komendy powinny mówić o „recipient”, nie sugerować administracyjnego ACL, i dokumentować, że każdy odbiorca może delegować poza audytem.

13. **WYSOKIE — kopiowanie prywatnej identity do każdego `.git/` mnoży sekret o szerokim zasięgu.** Jedna identity może otwierać wiele repozytoriów; jej wyciek jest gorszy niż wyciek jednego klucza repo. Na Windows obecny atomic writer nie zawęża ACL (`src/util/atomic.rs:91-98`). Należy rozważyć chroniony globalny magazyn/agent i lokalną referencję zamiast kopii. Kopiowanie wymaga jawnego opt-in oraz raportowania faktycznych zabezpieczeń.

14. **WYSOKIE — `export-key` obchodzi model odbiorców.** Eksport pełnego keyringu tworzy nieodwoływalną capability. Nie powinien automatycznie dziedziczyć semantyki v0.1: potrzebuje jawnego zakresu `key_id`, osobnej niebezpiecznej formy i komunikatu, że późniejsze usunięcie odbiorcy nie zadziała na tę kopię.

15. **ŚREDNIE — brak polityki utraty i rotacji identity.** Utrata jedynej źródłowej identity po `lock` może utracić cały keyring. Usunięcie ostatniego odbiorcy z kompletem historycznych kluczy powinno być odmową lub wymagać jawnego escape hatch. Potrzebny jest też przepływ wymiany identity urządzenia bez chwilowej utraty dostępu.

16. **ŚREDNIE — wszystkie sekrety trafiają do długowiecznego procesu.** Runtime keyring wielu kluczy zwiększa skutek dumpu pamięci. Typy private/master key muszą używać `ZeroizeOnDrop`, nie implementować `Debug`, ograniczać `Clone`, limitować parsery i otwierać tylko potrzebne klucze. Obecny eksport świadomie zeroizuje bufor (`src/crypto/keyfile.rs:173-197`) i ten standard musi zostać zachowany.

### User experience

17. **WYSOKIE — generowanie nazw z label ma trudne kolizje międzyplatformowe.** `Robert/Laptop`, `Robert-Laptop`, różna wielkość liter, Unicode normalization, nazwy zastrzeżone Windows, końcowe kropki/spacje i limit 255 bajtów mogą mapować się na ten sam plik. Katalog może leżeć w repozytorium albo prowadzić tam przez symlink/reparse point. Trzeba odziedziczyć ochronę `export-key` przed wszystkimi worktree (`src/commands/export_key.rs:151`) i zdefiniować retry po połowicznym zapisie pary.

18. **WYSOKIE — dwuplikowe `identity generate` nie jest atomowe jako para.** Helper gwarantuje atomowość jednego pliku, nie dwóch (`src/util/atomic.rs:13-16`, `:107-135`). Bezpieczny retry powinien umieć odtworzyć publiczny plik z istniejącego poprawnego private; nie może utknąć na ogólnej odmowie nadpisania.

19. **WYSOKIE — brakuje bezplikowego przepływu CI.** Instalowanie private identity w workspace lub cache runnera zostawia długowieczne kopie. Potrzebne jest wejście przez stdin/agent/keystore i cleanup; inaczej użytkownicy przeniosą sekret do argv lub środowiska. Obecny bezpieczniejszy precedens dla klucza istnieje w `unlock --key` (`context/foundation/zalozenia.md:202-209`).

20. **ŚREDNIE — `list-users` jako lista będzie kłamać.** UX musi pokazywać macierz odbiorca × klucz/generacja, wskazywać full/partial/future access i rozdzielać roster HEAD od historycznych grantów. Operacje po skróconym ID powinny przed zmianą wypisać pełne rozwiązane ID i label; skrypty powinny wymagać pełnego ID.

21. **ŚREDNIE — komunikaty `lock` muszą zależeć od rodzaju materiału.** Ostrzeżenie v0.1 o jedynej kopii klucza jest właściwe dla bezpośredniego keyringu, ale fałszywe dla zainstalowanej identity mającej źródłową kopię poza repo (`context/foundation/zalozenia.md:171-199`).

## Architecture Insights

Minimalny model danych, który wynika z analizy, lecz wymaga osobnych decyzji projektowych:

- wersjonowany, kanoniczny `key-manifest`: `repo_id`, `generation`, `active_key_id`, pełne fingerprinty wymaganych kluczy, roster/policy odbiorców;
- koperta per `(repo_id, identity_id, key fingerprint/key_id)` z całą metadaną związaną wewnątrz payloadu;
- lokalny runtime state w Git common dir związany z digestem/generacją manifestu;
- direct keyring i identity provider implementujące ten sam neutralny interfejs wielu kluczy;
- state machine rotacji z pending/prepared/active zamiast kilku niezależnych zapisów;
- S-11 zachowujący stare klucze do zakończenia publikacji i zdalnej weryfikacji.

To nie rozstrzyga najtrudniejszego kompromisu: lokalny cache odszyfrowanych kluczy naprawia checkout i UX, ale łamie decyzję „klucze odzyskane z kopert tylko w pamięci”. Cache samych kopert nie naprawia bootstrapu, jeśli wymaganej koperty nie ma jeszcze w bieżącym worktree. Ten punkt jest blockerem, nie detalem implementacyjnym.

## Historical Context

- Obecny `status` już ustanawia zasadę, że brak możliwości sprawdzenia nie oznacza sukcesu; shallow i partial clone są raportowane jako `undetermined` (`src/commands/status.rs:1118-1135`). S-10/S-11 muszą zachować ten przechył.
- Historia jest skanowana po lokalnie osiągalnych refach, ale lokalny fetch nie dowodzi kompletności zdalnego uniwersum. Dla S-11 trzeba jawnie zdefiniować authoritative remote i scope publikowanych refów.
- `lock` już pokazał, że linked worktrees i wyścigi są realnym źródłem pozostawienia plaintextu; rotacja i zmiana odbiorców muszą używać wspólnego locka oraz badać wszystkie worktree (`tests/lock_unlock.rs:221`).
- Format bloba jest zamrożony i już niesie `key_id`, więc multi-key odczyt nie wymaga zmiany danych (`src/crypto/format.rs:15-22`).

## Recommended Decision Order

1. Ustalić capability model albo osobną autoryzację administracyjną.
2. Ustalić `repo_id`, kanoniczny manifest, generation i autorytet `active_key_id`.
3. Rozwiązać checkout/runtime source bez zależności od kolejności worktree.
4. Zaprojektować transakcję i recovery state machine `rotate-key`.
5. Zamrozić semantykę full/partial grant oraz remove+rotate.
6. Zdefiniować macierz i werdykty `status`/`list-users`.
7. Rozstrzygnąć globalny magazyn identity, Windows ACL i CI stdin/agent.
8. Dopiero potem zamrażać formaty plików, rozszerzenia i dokładne CLI.

## Open Questions

1. Czy każdy odbiorca może świadomie delegować dostęp, czy istnieje oddzielny administrator?
2. Czy `add-user` domyślnie przyznaje całą oficjalną historię?
3. Czy `remove-user` ma zawsze wykonywać/uruchamiać rotację klucza dla przyszłości?
4. Gdzie jest autorytatywny manifest i `active_key_id` dla clean podczas checkoutu historycznego stanu?
5. Czy wolno zapisać odszyfrowany runtime keyring w `.git/`, czy decyzja „RAM only” jest bezwzględna?
6. Jaki jest authoritative remote i zbiór refów objętych S-11?
7. Czy S-09 może wejść bez rozwiązania Windows ACL dla identity otwierającej wiele repozytoriów?

## Code References

- `context/foundation/roadmap.md:37-94` — aktualny kontrakt S-09/S-10/S-11.
- [`src/crypto/format.rs:15-22`](https://github.com/rkarpin1/git-xcrypt/blob/9924d0c7c714c78fad19ab5ed0c34bff78949181/src/crypto/format.rs#L15-L22) — zamrożony blobowy `key_id`.
- [`src/crypto/key.rs:76-83`](https://github.com/rkarpin1/git-xcrypt/blob/9924d0c7c714c78fad19ab5ed0c34bff78949181/src/crypto/key.rs#L76-L83) — 64-bitowe wyprowadzenie `key_id`.
- [`src/crypto/keyfile.rs:173-197`](https://github.com/rkarpin1/git-xcrypt/blob/9924d0c7c714c78fad19ab5ed0c34bff78949181/src/crypto/keyfile.rs#L173-L197) — istniejący standard zeroizacji materiału eksportowanego.
- [`src/util/atomic.rs:13-16`](https://github.com/rkarpin1/git-xcrypt/blob/9924d0c7c714c78fad19ab5ed0c34bff78949181/src/util/atomic.rs#L13-L16) — atomowość dotyczy pojedynczego pliku.
- [`src/util/atomic.rs:91-98`](https://github.com/rkarpin1/git-xcrypt/blob/9924d0c7c714c78fad19ab5ed0c34bff78949181/src/util/atomic.rs#L91-L98) — brak zawężenia ACL poza Unix.
- [`src/commands/export_key.rs:151`](https://github.com/rkarpin1/git-xcrypt/blob/9924d0c7c714c78fad19ab5ed0c34bff78949181/src/commands/export_key.rs#L151) — ochrona celu eksportu względem worktree.
- [`src/commands/status.rs:1118-1135`](https://github.com/rkarpin1/git-xcrypt/blob/9924d0c7c714c78fad19ab5ed0c34bff78949181/src/commands/status.rs#L1118-L1135) — fail-closed dla partial/shallow.
- [`tests/lock_unlock.rs:221`](https://github.com/rkarpin1/git-xcrypt/blob/9924d0c7c714c78fad19ab5ed0c34bff78949181/tests/lock_unlock.rs#L221) — linked worktrees jako realna granica bezpieczeństwa.

## Related Research

Brak wcześniejszego aktywnego dokumentu badawczego dla S-09; decyzje wejściowe znajdują się bezpośrednio w `context/foundation/roadmap.md`.
