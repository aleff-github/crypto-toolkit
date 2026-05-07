'use strict';

const state = {
  inputBoxResponses: [],
  quickPickResponses: [],
  infoMessages: [],
  warningMessages: [],
  errorMessages: [],
  clipboardText: ''
};

function nextResponse(queue) {
  return queue.length > 0 ? queue.shift() : undefined;
}

module.exports = {
  __state: state,
  __reset() {
    state.inputBoxResponses = [];
    state.quickPickResponses = [];
    state.infoMessages = [];
    state.warningMessages = [];
    state.errorMessages = [];
    state.clipboardText = '';
  },
  __setInputBoxResponses(values) {
    state.inputBoxResponses = [...values];
  },
  __setQuickPickResponses(values) {
    state.quickPickResponses = [...values];
  },
  window: {
    activeTextEditor: undefined,
    showInputBox: async () => nextResponse(state.inputBoxResponses),
    showQuickPick: async () => nextResponse(state.quickPickResponses),
    showInformationMessage: async (message) => {
      state.infoMessages.push(message);
      return undefined;
    },
    showWarningMessage: async (message) => {
      state.warningMessages.push(message);
      return undefined;
    },
    showErrorMessage: async (message) => {
      state.errorMessages.push(message);
      return undefined;
    },
    createWebviewPanel: () => ({ webview: { html: '' } })
  },
  workspace: {
    getConfiguration: () => ({
      get: (_key, fallback) => fallback
    })
  },
  env: {
    clipboard: {
      writeText: async (text) => {
        state.clipboardText = text;
      }
    }
  },
  commands: {
    registerCommand: () => ({ dispose() {} })
  },
  ViewColumn: { Beside: 2 },
  EndOfLine: { LF: 1, CRLF: 2 },
  Selection: class Selection {}
};
