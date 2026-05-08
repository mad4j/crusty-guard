# crusty-guard

CLI Rust modulare per la verifica di vulnerabilità di rete.

## Funzionalità

- modulo `discovery` che rileva le porte TCP raggiungibili e produce un report riusabile
- modulo `checks` che esegue verifiche di vulnerabilità sul report di discovery
- check iniziale per `CVE-1999-0524` (esposizione del servizio finger)
- output in formato `text` oppure `json`

## Utilizzo

```bash
cargo run -- --host 127.0.0.1 --ports 79 --format text
cargo run -- --host 127.0.0.1 --ports 79 --format json
```

## Architettura

- `src/discovery.rs`: raccolta informazioni sul target
- `src/checks/`: verifiche modulari delle vulnerabilità
- `src/output/`: serializzazione del report in testo o JSON

Per aggiungere una nuova verifica è sufficiente creare un nuovo modulo in `src/checks/` e registrarlo in `run_all`.
