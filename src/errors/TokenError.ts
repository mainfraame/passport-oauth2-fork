/**
 * `TokenError` error.
 *
 * TokenError represents an error received from a token endpoint.  For details,
 * refer to RFC 6749, section 5.2.
 *
 * References:
 *   - [The OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/rfc6749)
 *
 * @constructor
 * @param {String} [message]
 * @param {String} [code]
 * @param {String} [uri]
 * @param {Number} [status]
 * @api public
 */
export class TokenError extends Error {
  code: string;
  status: number;
  uri: string;

  constructor(message?, code?, uri?, status?) {
    super();

    this.name = this.constructor.name;
    this.message = message;
    this.code = code || 'invalid_request';
    this.uri = uri;
    this.status = status || 500;

    Error.captureStackTrace(this, this.constructor);
  }
}
