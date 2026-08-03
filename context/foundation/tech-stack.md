---
starter_id: rust
package_manager: cargo
project_name: git-crypt
hints:
  language_family: rust
  team_size: solo
  deployment_target: self-host
  ci_provider: github-actions
  ci_default_flow: manual-promotion
  bootstrapper_confidence: verified
  path_taken: standard
  quality_override: false
  self_check_answers: null
  has_auth: false
  has_payments: false
  has_realtime: false
  has_ai: false
  has_background_jobs: false
---

## Why this stack

Pojedynczy deweloper budujący narzędzie wiersza poleceń do szyfrowania plików w repozytorium git, w 6 tygodni pracy po godzinach. `rust` jest sprawdzoną rekomendacją dla pary `(cli, rust)` i przechodzi wszystkie cztery bramki przyjazności dla agenta: jawne typy, konwencje `cargo`, silna obecność w danych treningowych i aktualna dokumentacja. Pewność scaffoldowania to `verified`, więc inicjacja przebiegnie bez tarcia — tym bardziej, że katalog zawiera już crate binarny z edycją 2024, dokładnie taki, jaki wygenerowałby starter. Wymóg samowystarczalnej binarki bez zewnętrznych bibliotek (FR-011) i deterministycznego szyfrowania czyni Rust naturalnym wyborem, a nie kompromisem. Cel wdrożenia to `self-host` — produkt nie ma komponentu serwerowego, użytkownik instaluje binarkę u siebie. CI na GitHub Actions z wydaniem sterowanym ręcznie zamiast automatycznego przy merge: dla dystrybuowanej binarki publikowanie release'u przy każdej zmianie w `main` byłoby błędem. Żadna z pięciu funkcji wymuszających technologię (logowanie, płatności, czas rzeczywisty, AI, zadania w tle) nie występuje w tym produkcie.
