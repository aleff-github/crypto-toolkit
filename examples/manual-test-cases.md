# Crypto Toolkit v0.6.0 manual test cases

Use `manual-playground.txt` as the source file.

## Key checks

- `Crypto` menu appears when the editor has focus, even with no text selected.
- Without a selection, only cursor-friendly Utility commands should be useful: UUID, random values, and Unix timestamp now.
- Selection-based categories such as Encode, Decode, Hash, HMAC, JWT, AES, and Smart are guarded by `editorHasSelection` in the menu.
- `Crypto -> JWT -> Decode JWT` is the only visible JWT action.
- There is no visible Recipes menu, Web Security menu, JWT Sign/Verify commands, Copy Header/Payload commands, Regex Extract, or AES-CTR.
- JWT Decode respects `cryptoToolkit.outputMode` and does not force side panel.
- Smart Detect still opens a clean side panel.
- Malformed inputs show clean VS Code errors and never crash the extension.
