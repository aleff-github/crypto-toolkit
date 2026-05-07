'use strict';

const Module = require('module');
const path = require('path');
const originalLoad = Module._load;
const vscodeMockPath = path.join(__dirname, 'vscodeMock.js');

Module._load = function patchedLoad(request, parent, isMain) {
  if (request === 'vscode') {
    return require(vscodeMockPath);
  }
  return originalLoad.call(this, request, parent, isMain);
};
