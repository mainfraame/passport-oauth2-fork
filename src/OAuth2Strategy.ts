import crypto from 'crypto';
import url from 'url';

import { OAuth2 } from 'oauth';
import { Strategy } from 'passport-strategy';

import { AuthorizationError, InternalOAuthError, TokenError } from './errors';
import { NonceStore, NullStore, PKCESessionStore, StateStore } from './state';
import { base64Url, originalURL } from './utils';

/**
 * Creates an instance of `OAuth2Strategy`.
 *
 * The OAuth 2.0 authentication OAuth2Strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new OAuth2Strategy({
 *         authorizationURL: 'https://www.example.com/oauth2/authorize',
 *         tokenURL: 'https://www.example.com/oauth2/token',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

export class OAuth2Strategy extends Strategy {
  name;
  _verify;
  _oauth2;
  _callbackURL;
  _key;
  _scope;
  _scopeSeparator;
  _stateStore;
  _pkceMethod;
  _trustProxy;
  _passReqToCallback;
  _skipUserProfile;
  fail;
  error;

  constructor(options, verify?) {
    if (typeof options == 'function') {
      verify = options;
      options = undefined;
    }
    options = options || {};

    if (!verify) {
      throw new TypeError('OAuth2Strategy requires a verify callback');
    }
    if (!options.authorizationURL) {
      throw new TypeError('OAuth2Strategy requires a authorizationURL option');
    }
    if (!options.tokenURL) {
      throw new TypeError('OAuth2Strategy requires a tokenURL option');
    }
    if (!options.clientID) {
      throw new TypeError('OAuth2Strategy requires a clientID option');
    }

    super();

    this.name = 'oauth2';
    this._verify = verify;

    // NOTE: The _oauth2 property is considered "protected".  Subclasses are
    //       allowed to use it when making protected resource requests to retrieve
    //       the user profile.
    this._oauth2 = new OAuth2(
      options.clientID,
      options.clientSecret,
      '',
      options.authorizationURL,
      options.tokenURL,
      options.customHeaders
    );

    this._callbackURL = options.callbackURL;
    this._scope = options.scope;
    this._scopeSeparator = options.scopeSeparator || ' ';
    this._pkceMethod = options.pkce === true ? 'S256' : options.pkce;
    this._key =
      options.sessionKey ||
      'oauth2:' + url.parse(options.authorizationURL).hostname;

    if (options.store && typeof options.store == 'object') {
      this._stateStore = options.store;
    } else if (options.store) {
      this._stateStore = options.pkce
        ? new PKCESessionStore({ key: this._key })
        : new StateStore({ key: this._key });
    } else if (options.state) {
      this._stateStore = options.pkce
        ? new PKCESessionStore({ key: this._key })
        : new NonceStore({ key: this._key });
    } else {
      if (options.pkce) {
        throw new TypeError(
          'OAuth2Strategy requires `state: true` option when PKCE is enabled'
        );
      }
      this._stateStore = new NullStore();
    }

    this._trustProxy = options.proxy;
    this._passReqToCallback = options.passReqToCallback;
    this._skipUserProfile =
      options.skipUserProfile === undefined ? false : options.skipUserProfile;
  }

  /**
   * Authenticate request by delegating to a service provider using OAuth 2.0.
   *
   * @param {Object} req
   * @param {Object} options
   * @api protected
   */

  authenticate(req, options) {
    options = options || {};

    if (req.query && req.query.error) {
      if (req.query.error == 'access_denied') {
        return this.fail({ message: req.query.error_description });
      } else {
        return this.error(
          new AuthorizationError(
            req.query.error_description,
            req.query.error,
            req.query.error_uri
          )
        );
      }
    }

    let callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      const parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(
          originalURL(req, { proxy: this._trustProxy }),
          callbackURL
        );
      }
    }

    const meta = {
      authorizationURL: this._oauth2._authorizeUrl,
      tokenURL: this._oauth2._accessTokenUrl,
      clientID: this._oauth2._clientId,
      callbackURL: callbackURL
    };

    if (req.query && req.query.code) {
      const loaded = (err, ok, state) => {
        if (err) {
          return this.error(err);
        }
        if (!ok) {
          return this.fail(state, 403);
        }

        const code = req.query.code;

        const params = this.tokenParams(options) as any;
        params.grant_type = 'authorization_code';
        if (callbackURL) {
          params.redirect_uri = callbackURL;
        }
        if (typeof ok == 'string') {
          // PKCE
          params.code_verifier = ok;
        }

        this._oauth2.getOAuthAccessToken(
          code,
          params,
          (err, accessToken, refreshToken, params) => {
            if (err) {
              return this.error(
                this._createOAuthError('Failed to obtain access token', err)
              );
            }
            if (!accessToken) {
              return this.error(new Error('Failed to obtain access token'));
            }

            this._loadUserProfile(accessToken, (err, profile) => {
              if (err) {
                return this.error(err);
              }

              const verified = (err, user, info) => {
                if (err) {
                  return this.error(err);
                }
                if (!user) {
                  return this.fail(info);
                }

                info = info || {};
                if (state) {
                  info.state = state;
                }
                this.success(user, info);
              };

              try {
                if (this._passReqToCallback) {
                  const arity = this._verify.length;
                  if (arity == 6) {
                    this._verify(
                      req,
                      accessToken,
                      refreshToken,
                      params,
                      profile,
                      verified
                    );
                  } else {
                    // arity == 5
                    this._verify(
                      req,
                      accessToken,
                      refreshToken,
                      profile,
                      verified
                    );
                  }
                } else {
                  const arity = this._verify.length;
                  if (arity == 5) {
                    this._verify(
                      accessToken,
                      refreshToken,
                      params,
                      profile,
                      verified
                    );
                  } else {
                    // arity == 4
                    this._verify(accessToken, refreshToken, profile, verified);
                  }
                }
              } catch (ex) {
                return this.error(ex);
              }
            });
          }
        );
      };

      const state = req.query.state;
      try {
        const arity = this._stateStore.verify.length;
        if (arity == 4) {
          this._stateStore.verify(req, state, meta, loaded);
        } else {
          // arity == 3
          this._stateStore.verify(req, state, loaded);
        }
      } catch (ex) {
        return this.error(ex);
      }
    } else {
      const params = this.authorizationParams(options) as any;
      params.response_type = 'code';
      if (callbackURL) {
        params.redirect_uri = callbackURL;
      }
      let scope = options.scope || this._scope;
      if (scope) {
        if (Array.isArray(scope)) {
          scope = scope.join(this._scopeSeparator);
        }
        params.scope = scope;
      }
      let verifier, challenge;

      if (this._pkceMethod) {
        verifier = base64Url(crypto.pseudoRandomBytes(32));
        switch (this._pkceMethod) {
          case 'plain':
            challenge = verifier;
            break;
          case 'S256':
            challenge = base64Url(
              crypto.createHash('sha256').update(verifier).digest()
            );
            break;
          default:
            return this.error(
              new Error(
                'Unsupported code verifier transformation method: ' +
                this._pkceMethod
              )
            );
        }

        params.code_challenge = challenge;
        params.code_challenge_method = this._pkceMethod;
      }

      const state = options.state;
      if (state && typeof state == 'string') {
        // NOTE: In passport-oauth2@1.5.0 and earlier, `state` could be passed as
        //       an object.  However, it would result in an empty string being
        //       serialized as the value of the query parameter by `url.format()`,
        //       effectively ignoring the option.  This implies that `state` was
        //       only functional when passed as a string value.
        //
        //       This fact is taken advantage of here to fall into the `else`
        //       branch below when `state` is passed as an object.  In that case
        //       the state will be automatically managed and persisted by the
        //       state store.
        params.state = state;

        const parsed = url.parse(this._oauth2._authorizeUrl, true);

        parsed.query = {
          ...parsed.query,
          ...params,
          client_id: this._oauth2._clientId
        };

        delete parsed.search;
        // merge(parsed.query, params);
        this.redirect(url.format(parsed));
      } else {
        const stored = (err, state) => {
          if (err) {
            return this.error(err);
          }

          if (state) {
            params.state = state;
          }

          const parsed = url.parse(this._oauth2._authorizeUrl, true);

          parsed.query = {
            ...parsed.query,
            ...params,
            client_id: this._oauth2._clientId
          };

          delete parsed.search;

          this.redirect(url.format(parsed));
        };

        try {
          const arity = this._stateStore.store.length;
          if (arity == 5) {
            this._stateStore.store(req, verifier, state, meta, stored);
          } else if (arity == 4) {
            this._stateStore.store(req, state, meta, stored);
          } else if (arity == 3) {
            this._stateStore.store(req, meta, stored);
          } else {
            // arity == 2
            this._stateStore.store(req, stored);
          }
        } catch (ex) {
          return this.error(ex);
        }
      }
    }
  }

  /**
   * Retrieve user profile from service provider.
   *
   * OAuth 2.0-based authentication strategies can overrride this function in
   * order to load the user's profile from the service provider.  This assists
   * applications (and users of those applications) in the initial registration
   * process by automatically submitting required information.
   *
   * @param {String} accessToken
   * @param {Function} done
   * @api protected
   */
  userProfile(accessToken, done) {
    return done(null, {});
  }

  /**
   * Return extra parameters to be included in the authorization request.
   *
   * Some OAuth 2.0 providers allow additional, non-standard parameters to be
   * included when requesting authorization.  Since these parameters are not
   * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
   * strategies can overrride this function in order to populate these parameters
   * as required by the provider.
   *
   * @return {Object}
   * @api protected
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  authorizationParams(options?) {
    return {};
  }

  /**
   * Return extra parameters to be included in the token request.
   *
   * Some OAuth 2.0 providers allow additional, non-standard parameters to be
   * included when requesting an access token.  Since these parameters are not
   * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
   * strategies can overrride this function in order to populate these parameters
   * as required by the provider.
   *
   * @return {Object}
   * @api protected
   */

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  tokenParams(options?) {
    return {};
  }

  /**
   * Parse error response from OAuth 2.0 endpoint.
   *
   * OAuth 2.0-based authentication strategies can overrride this function in
   * order to parse error responses received from the token endpoint, allowing the
   * most informative message to be displayed.
   *
   * If this function is not overridden, the body will be parsed in accordance
   * with RFC 6749, section 5.2.
   *
   * @param {String} body
   * @param {Number} status
   * @return {Error|null}
   * @api protected
   */
  parseErrorResponse(body, status?): Error | null {
    const json = JSON.parse(body);
    if (json.error) {
      return new TokenError(
        json.error_description,
        json.error,
        json.error_uri,
        status
      );
    }
    return null;
  }

  /**
   * Load user profile, contingent upon options.
   *
   * @param {String} accessToken
   * @param {Function} done
   * @api private
   */
  _loadUserProfile(accessToken, done) {
    const loadIt = () => {
      return this.userProfile(accessToken, done);
    };

    function skipIt() {
      return done(null);
    }

    if (
      typeof this._skipUserProfile == 'function' &&
      this._skipUserProfile.length > 1
    ) {
      // async
      this._skipUserProfile(accessToken, function (err, skip) {
        if (err) {
          return done(err);
        }
        if (!skip) {
          return loadIt();
        }
        return skipIt();
      });
    } else {
      const skip =
        typeof this._skipUserProfile == 'function'
          ? this._skipUserProfile()
          : this._skipUserProfile;
      if (!skip) {
        return loadIt();
      }
      return skipIt();
    }
  }
  /**
   * Create an OAuth error.
   *
   * @param {String} message
   * @param {Object|Error} err
   * @api private
   */
  _createOAuthError(message, err) {
    let e;
    if (err.statusCode && err.data) {
      try {
        e = this.parseErrorResponse(err.data, err.statusCode);
      } catch (_) {
        //
      }
    }
    if (!e) {
      e = new InternalOAuthError(message, err);
    }
    return e;
  }
}
