/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy, assuming that the proxy has been flagged as trusted.
 *
 * @param {http.IncomingMessage} req
 * @param {Object} [options]
 * @return {String}
 * @api private
 */
export const originalURL = (req, options) => {
  options = options || {};
  const app = req.app;
  if (app && app.get && app.get('trust proxy')) {
    options.proxy = true;
  }
  const trustProxy = options.proxy;

  const proto = (req.headers['x-forwarded-proto'] || '').toLowerCase(),
    tls =
      /** prefer req.socket; chai required req.connection */
      (req.socket?.encrypted ?? req.connection?.encrypted) ||
      (trustProxy && 'https' == proto.split(/\s*,\s*/)[0]),
    host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host,
    protocol = tls ? 'https' : 'http',
    path = req.url || '';
  return protocol + '://' + host + path;
};

function fromBase64(base64: string): string {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function base64Url(
  input: string | Buffer,
  encoding: BufferEncoding = 'utf8'
): string {
  if (Buffer.isBuffer(input)) {
    return fromBase64(input.toString('base64'));
  }
  return fromBase64(Buffer.from(input as string, encoding).toString('base64'));
}
