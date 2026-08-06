---
change_id: attribute-stack-walks-ancestors
title: Read .gitattributes from the path's ancestors, not the whole working tree
status: new
created: 2026-08-06
updated: 2026-08-06
archived_at: null
---

## Notes

wczytywać `.gitattributes` z katalogów na ścieżce pytanego pliku, tak jak robi git, zamiast przechodzić całe drzewo robocze (src/git/attributes.rs::collect_attribute_files). Zmierzone: `git add` jednego zadeklarowanego pliku w repozytorium z dużym katalogiem budowania kosztuje 220 ms zamiast 10 ms.

Pochodzenie: przegląd `emi-code-review-auto-fix` z 2026-08-06, runda 2. Pomiary, warianty przycięcia odrzucone wraz z powodami oraz trzy konsekwencje warte świadomej decyzji są zapisane w `context/runs/2026-08-06-code-review-auto-fix.md` → „Otwarte — do decyzji właściciela" poz. 1. Runda świadomie nie naprawiła tego sama, bo zmiana dotyka ładowania predykatu, na którym stoi odmowa ścieżki `clean`.
