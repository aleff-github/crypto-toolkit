import { Operation } from '../commands/types';
import { fromBase64, fromBase64Url, fromHex, toBase64Url } from '../crypto/buffer';
import { UserFacingError } from '../utils/errors';

function htmlEncodeText(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function htmlDecodeText(input: string): string {
  const named: Record<string, string> = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    '#39': "'"
  };

  return input.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]+);/g, (match, entity: string) => {
    if (Object.prototype.hasOwnProperty.call(named, entity)) {
      return named[entity];
    }

    if (entity.startsWith('#x')) {
      return String.fromCodePoint(Number.parseInt(entity.slice(2), 16));
    }

    if (entity.startsWith('#')) {
      return String.fromCodePoint(Number.parseInt(entity.slice(1), 10));
    }

    return match;
  });
}

export const base64Encode: Operation = {
  id: 'cryptoToolkit.encode.base64',
  title: 'Base64 Encode',
  run(input) {
    return { text: Buffer.from(input, 'utf8').toString('base64'), language: 'plaintext' };
  }
};

export const base64UrlEncode: Operation = {
  id: 'cryptoToolkit.encode.base64url',
  title: 'Base64URL Encode',
  run(input) {
    return { text: toBase64Url(Buffer.from(input, 'utf8')), language: 'plaintext' };
  }
};

export const hexEncode: Operation = {
  id: 'cryptoToolkit.encode.hex',
  title: 'Hex Encode',
  run(input) {
    return { text: Buffer.from(input, 'utf8').toString('hex'), language: 'plaintext' };
  }
};

export const urlEncode: Operation = {
  id: 'cryptoToolkit.encode.url',
  title: 'URL Encode',
  run(input) {
    return { text: encodeURIComponent(input), language: 'plaintext' };
  }
};

export const htmlEncode: Operation = {
  id: 'cryptoToolkit.encode.html',
  title: 'HTML Encode',
  run(input) {
    return { text: htmlEncodeText(input), language: 'plaintext' };
  }
};

export const base64Decode: Operation = {
  id: 'cryptoToolkit.decode.base64',
  title: 'Base64 Decode',
  run(input) {
    return { text: fromBase64(input).toString('utf8'), language: 'plaintext' };
  }
};

export const base64UrlDecode: Operation = {
  id: 'cryptoToolkit.decode.base64url',
  title: 'Base64URL Decode',
  run(input) {
    return { text: fromBase64Url(input).toString('utf8'), language: 'plaintext' };
  }
};

export const hexDecode: Operation = {
  id: 'cryptoToolkit.decode.hex',
  title: 'Hex Decode',
  run(input) {
    return { text: fromHex(input).toString('utf8'), language: 'plaintext' };
  }
};

export const urlDecode: Operation = {
  id: 'cryptoToolkit.decode.url',
  title: 'URL Decode',
  run(input) {
    try {
      return { text: decodeURIComponent(input), language: 'plaintext' };
    } catch {
      throw new UserFacingError('URL Decode failed.', {
        reason: 'The selected text contains malformed percent-encoding.',
        expected: 'Percent sequences must be complete, for example %20 or %2F.',
        hint: 'Check for lone % characters or copy only the encoded value before decoding.'
      });
    }
  }
};

export const htmlDecode: Operation = {
  id: 'cryptoToolkit.decode.html',
  title: 'HTML Decode',
  run(input) {
    return { text: htmlDecodeText(input), language: 'plaintext' };
  }
};
