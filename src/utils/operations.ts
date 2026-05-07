import * as vscode from 'vscode';
import { randomBytes, randomUUID } from 'crypto';
import { Operation } from '../commands/types';
import { UserFacingError } from './errors';

function parseJson(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'JSON.parse failed.';
    throw new UserFacingError('Malformed JSON input. JSON operation failed.', {
      reason: message,
      expected: 'A complete JSON object, array, string, number, boolean, or null.',
      hint: 'Check quotes, trailing commas, missing braces, or decode URL/Base64 first if this JSON is nested.'
    });
  }
}

export const jsonPretty: Operation = {
  id: 'cryptoToolkit.utility.jsonPretty',
  title: 'JSON Pretty',
  run(input) {
    return { text: JSON.stringify(parseJson(input), null, 2), language: 'json' };
  }
};

export const jsonMinify: Operation = {
  id: 'cryptoToolkit.utility.jsonMinify',
  title: 'JSON Minify',
  run(input) {
    return { text: JSON.stringify(parseJson(input)), language: 'json' };
  }
};

export const unixDecode: Operation = {
  id: 'cryptoToolkit.utility.unixDecode',
  title: 'Unix Timestamp Decode',
  run(input) {
    const raw = input.trim();
    if (!/^\d{10,13}$/.test(raw)) {
      throw new UserFacingError('Unix Timestamp Decode failed.', {
      reason: `The selection is ${raw.length} character(s) long and is not a 10- or 13-digit numeric timestamp.`,
      expected: '10 digits for seconds or 13 digits for milliseconds.',
      hint: 'Select only the timestamp value, without quotes, JSON field names, or surrounding text.'
    });
    }

    const number = Number(raw);
    const ms = raw.length === 13 ? number : number * 1000;
    const date = new Date(ms);

    if (Number.isNaN(date.getTime())) {
      throw new UserFacingError('Unix Timestamp Decode failed.', {
      reason: 'The numeric value could not be converted into a valid JavaScript Date.',
      hint: 'Check whether the value is seconds, milliseconds, or a different timestamp format.'
    });
    }

    return {
      text: JSON.stringify({ unixInput: raw, iso: date.toISOString(), utc: date.toUTCString(), local: date.toString() }, null, 2),
      language: 'json'
    };
  }
};

export const unixEncode: Operation = {
  id: 'cryptoToolkit.utility.unixEncode',
  title: 'Unix Timestamp Encode',
  allowEmptyInput: true,
  run(input) {
    const trimmed = input.trim();
    const date = trimmed.length > 0 ? new Date(trimmed) : new Date();

    if (Number.isNaN(date.getTime())) {
      throw new UserFacingError('Unix Timestamp Encode failed.', {
      reason: 'The selected text could not be parsed as a JavaScript date.',
      expected: 'ISO-8601 text such as 2026-05-06T12:30:00Z, or no selection for the current time.',
      hint: 'Remove surrounding labels or select only the date/time value.'
    });
    }

    return {
      text: JSON.stringify({ iso: date.toISOString(), seconds: Math.floor(date.getTime() / 1000), milliseconds: date.getTime() }, null, 2),
      language: 'json'
    };
  }
};

export const uuidGenerate: Operation = {
  id: 'cryptoToolkit.utility.uuidGenerate',
  title: 'Generate UUID',
  allowEmptyInput: true,
  run() {
    return { text: randomUUID(), language: 'plaintext' };
  }
};

export const randomHex: Operation = {
  id: 'cryptoToolkit.utility.randomHex',
  title: 'Generate Random Hex',
  allowEmptyInput: true,
  async run(_input, context) {
    const bytesText = await vscode.window.showInputBox({
      title: 'Crypto Toolkit: Random Hex',
      prompt: 'Number of secure random bytes.',
      value: String(context.settings.randomTokenBytes),
      validateInput(value) {
        const n = Number(value);
        return Number.isInteger(n) && n >= 1 && n <= 4096 ? undefined : 'Enter an integer from 1 to 4096.';
      },
      ignoreFocusOut: true
    });

    if (bytesText === undefined) {
      throw new UserFacingError('Operation cancelled.');
    }

    return { text: randomBytes(Number(bytesText)).toString('hex'), language: 'plaintext' };
  }
};

export const randomBase64: Operation = {
  id: 'cryptoToolkit.utility.randomBase64',
  title: 'Generate Random Base64',
  allowEmptyInput: true,
  async run(_input, context) {
    const bytesText = await vscode.window.showInputBox({
      title: 'Crypto Toolkit: Random Base64',
      prompt: 'Number of secure random bytes.',
      value: String(context.settings.randomTokenBytes),
      validateInput(value) {
        const n = Number(value);
        return Number.isInteger(n) && n >= 1 && n <= 4096 ? undefined : 'Enter an integer from 1 to 4096.';
      },
      ignoreFocusOut: true
    });

    if (bytesText === undefined) {
      throw new UserFacingError('Operation cancelled.');
    }

    return { text: randomBytes(Number(bytesText)).toString('base64'), language: 'plaintext' };
  }
};

export const sortLines: Operation = {
  id: 'cryptoToolkit.utility.sortLines',
  title: 'Sort Lines',
  run(input) {
    return { text: input.split(/\r?\n/).sort((a, b) => a.localeCompare(b)).join('\n'), language: 'plaintext' };
  }
};

export const uniqueLines: Operation = {
  id: 'cryptoToolkit.utility.uniqueLines',
  title: 'Unique Lines',
  run(input) {
    const seen = new Set<string>();
    const lines = input.split(/\r?\n/).filter((line) => {
      if (seen.has(line)) {
        return false;
      }
      seen.add(line);
      return true;
    });
    return { text: lines.join('\n'), language: 'plaintext' };
  }
};
