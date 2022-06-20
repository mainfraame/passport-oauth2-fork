import { nanoid } from 'nanoid';

/**
 * Creates an instance of `SessionStore`.
 *
 * This is the state store implementation for the OAuth2Strategy used when
 * the `state` option is enabled.  It generates a random state and stores it in
 * `req.session` and verifies it when the service provider redirects the user
 * back to the application.
 *
 * This state store requires session support.  If no session exists, an error
 * will be thrown.
 *
 * Options:
 *
 *   - `key`  The key in the session under which to store the state
 *
 * @constructor
 * @param {Object} options
 * @api public
 */
export class PKCESessionStore {
  _key;

  constructor(options) {
    if (!options.key) {
      throw new TypeError('Session-based state store requires a session key');
    }
    this._key = options.key;
  }

  /**
   * Store request state.
   *
   * This implementation simply generates a random string and stores the value in
   * the session, where it will be used for verification when the user is
   * redirected back to the application.
   *
   * @param {Object} req
   * @param {Object} verifier
   * @param {Object} state
   * @param {Object} meta
   * @param {Function} callback
   * @api protected
   */
  store(req, verifier, state, meta, callback) {
    if (!req.session) {
      return callback(
        new Error(
          'OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?'
        )
      );
    }

    const key = this._key;
    const sstate = {
      handle: nanoid(24),
      code_verifier: verifier,
      state: undefined
    };
    if (state) {
      sstate.state = state;
    }
    if (!req.session[key]) {
      req.session[key] = {};
    }
    req.session[key].state = sstate;
    callback(null, sstate.handle);
  }

  /**
   * Verify request state.
   *
   * This implementation simply compares the state parameter in the request to the
   * value generated earlier and stored in the session.
   *
   * @param {Object} req
   * @param {String} providedState
   * @param {Function} callback
   * @api protected
   */
  verify(req, providedState, callback) {
    if (!req.session) {
      return callback(
        new Error(
          'OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?'
        )
      );
    }

    const key = this._key;
    if (!req.session[key]) {
      return callback(null, false, {
        message: 'Unable to verify authorization request state.'
      });
    }

    const state = req.session[key].state;
    if (!state) {
      return callback(null, false, {
        message: 'Unable to verify authorization request state.'
      });
    }

    delete req.session[key].state;
    if (Object.keys(req.session[key]).length === 0) {
      delete req.session[key];
    }

    if (state.handle !== providedState) {
      return callback(null, false, {
        message: 'Invalid authorization request state.'
      });
    }

    return callback(null, state.code_verifier, state.state);
  }
}
