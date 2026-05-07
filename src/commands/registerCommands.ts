import * as vscode from 'vscode';
import { executeOperation } from './execution';
import { OperationLoader } from './types';

function registerLazyCommand(context: vscode.ExtensionContext, commandId: string, loader: OperationLoader): void {
  const disposable = vscode.commands.registerCommand(commandId, async () => {
    const operation = await loader();
    await executeOperation(operation, commandId);
  });

  context.subscriptions.push(disposable);
}

export function registerCommands(context: vscode.ExtensionContext): void {
  registerLazyCommand(context, 'cryptoToolkit.smart.detectAndDecode', async () => (await import('../smart/operations')).smartDetectAndDecode);

  registerLazyCommand(context, 'cryptoToolkit.encode.base64', async () => (await import('../encoders/operations')).base64Encode);
  registerLazyCommand(context, 'cryptoToolkit.encode.base64url', async () => (await import('../encoders/operations')).base64UrlEncode);
  registerLazyCommand(context, 'cryptoToolkit.encode.hex', async () => (await import('../encoders/operations')).hexEncode);
  registerLazyCommand(context, 'cryptoToolkit.encode.url', async () => (await import('../encoders/operations')).urlEncode);
  registerLazyCommand(context, 'cryptoToolkit.encode.html', async () => (await import('../encoders/operations')).htmlEncode);

  registerLazyCommand(context, 'cryptoToolkit.decode.base64', async () => (await import('../encoders/operations')).base64Decode);
  registerLazyCommand(context, 'cryptoToolkit.decode.base64url', async () => (await import('../encoders/operations')).base64UrlDecode);
  registerLazyCommand(context, 'cryptoToolkit.decode.hex', async () => (await import('../encoders/operations')).hexDecode);
  registerLazyCommand(context, 'cryptoToolkit.decode.url', async () => (await import('../encoders/operations')).urlDecode);
  registerLazyCommand(context, 'cryptoToolkit.decode.html', async () => (await import('../encoders/operations')).htmlDecode);

  registerLazyCommand(context, 'cryptoToolkit.hash.md5', async () => (await import('../hash/operations')).md5Hash);
  registerLazyCommand(context, 'cryptoToolkit.hash.sha1', async () => (await import('../hash/operations')).sha1Hash);
  registerLazyCommand(context, 'cryptoToolkit.hash.sha256', async () => (await import('../hash/operations')).sha256Hash);
  registerLazyCommand(context, 'cryptoToolkit.hash.sha512', async () => (await import('../hash/operations')).sha512Hash);

  registerLazyCommand(context, 'cryptoToolkit.hmac.sha256', async () => (await import('../hash/operations')).hmacSha256);
  registerLazyCommand(context, 'cryptoToolkit.hmac.sha384', async () => (await import('../hash/operations')).hmacSha384);
  registerLazyCommand(context, 'cryptoToolkit.hmac.sha512', async () => (await import('../hash/operations')).hmacSha512);

  registerLazyCommand(context, 'cryptoToolkit.jwt.decode', async () => (await import('../jwt/operations')).jwtDecode);

  registerLazyCommand(context, 'cryptoToolkit.aes.cbcEncrypt', async () => (await import('../aes/operations')).aesCbcEncrypt);
  registerLazyCommand(context, 'cryptoToolkit.aes.cbcDecrypt', async () => (await import('../aes/operations')).aesCbcDecrypt);
  registerLazyCommand(context, 'cryptoToolkit.aes.gcmEncrypt', async () => (await import('../aes/operations')).aesGcmEncrypt);
  registerLazyCommand(context, 'cryptoToolkit.aes.gcmDecrypt', async () => (await import('../aes/operations')).aesGcmDecrypt);

  registerLazyCommand(context, 'cryptoToolkit.utility.jsonPretty', async () => (await import('../utils/operations')).jsonPretty);
  registerLazyCommand(context, 'cryptoToolkit.utility.jsonMinify', async () => (await import('../utils/operations')).jsonMinify);
  registerLazyCommand(context, 'cryptoToolkit.utility.unixDecode', async () => (await import('../utils/operations')).unixDecode);
  registerLazyCommand(context, 'cryptoToolkit.utility.unixEncode', async () => (await import('../utils/operations')).unixEncode);
  registerLazyCommand(context, 'cryptoToolkit.utility.uuidGenerate', async () => (await import('../utils/operations')).uuidGenerate);
  registerLazyCommand(context, 'cryptoToolkit.utility.randomHex', async () => (await import('../utils/operations')).randomHex);
  registerLazyCommand(context, 'cryptoToolkit.utility.randomBase64', async () => (await import('../utils/operations')).randomBase64);
  registerLazyCommand(context, 'cryptoToolkit.utility.sortLines', async () => (await import('../utils/operations')).sortLines);
  registerLazyCommand(context, 'cryptoToolkit.utility.uniqueLines', async () => (await import('../utils/operations')).uniqueLines);
}
