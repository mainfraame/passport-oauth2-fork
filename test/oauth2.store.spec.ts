import uri from 'url';

import chai from 'chai';
import passport from 'chai-passport-strategy';

import { OAuth2Strategy } from '../src';

chai.use(passport);

/** todo:: req.session is not being persisted */
describe('OAuth2Strategy - store', function () {
  describe('using default session state store through store option', function () {
    describe('issuing authorization request', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: true
        },
        function () {}
      );

      describe('that redirects to service provider', function () {
        let request, url;

        beforeAll(function () {
          return new Promise((resolve) => {
            const pport = chai.passport.use(strategy);

            pport
              .redirect(function (u) {
                url = u;
                resolve(null);
              })
              .request(function (req) {
                request = req;
                req.session = {};
              })
              .authenticate();
          });
        });

        it('should be redirected', function () {
          const u = uri.parse(url, true);
          expect(u.query.state).toHaveLength(24);
        });

        it('should save state in session', function () {
          const u = uri.parse(url, true);

          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toHaveLength(24);
          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toEqual(u.query.state);
          expect(
            request.session['oauth2:www.example.com'].state.state
          ).toBeUndefined();
        });
      }); // that redirects to service provider

      describe('that redirects to service provider with state', function () {
        let request, url;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .redirect(function (u) {
                url = u;
                resolve(null);
              })
              .request(function (req) {
                request = req;
                req.session = {};
              })
              .authenticate({ state: { returnTo: '/somewhere' } });
          });
        });

        it('should be redirected', function () {
          const u = uri.parse(url, true);
          expect(u.query.state).toHaveLength(24);
        });

        it('should save state in session', function () {
          const u = uri.parse(url, true);

          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toHaveLength(24);
          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toEqual(u.query.state);
          expect(request.session['oauth2:www.example.com'].state.state).toEqual(
            { returnTo: '/somewhere' }
          );
        });
      }); // that redirects to service provider with state

      describe('that redirects to service provider with state set to boolean true', function () {
        let request, url;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .redirect(function (u) {
                url = u;
                resolve(null);
              })
              .request(function (req) {
                request = req;
                req.session = {};
              })
              .authenticate({ state: true });
          });
        });

        it('should be redirected', function () {
          const u = uri.parse(url, true);
          expect(u.query.state).toHaveLength(24);
        });

        it('should save state in session', function () {
          const u = uri.parse(url, true);

          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toHaveLength(24);
          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toEqual(u.query.state);
          expect(request.session['oauth2:www.example.com'].state.state).toEqual(
            true
          );
        });
      }); // that redirects to service provider with state set to boolean true

      describe('that redirects to service provider with state set to boolean false', function () {
        let request, url;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .redirect(function (u) {
                url = u;
                resolve(null);
              })
              .request(function (req) {
                request = req;
                req.session = {};
              })
              .authenticate({ state: false });
          });
        });

        it('should be redirected', function () {
          const u = uri.parse(url, true);
          expect(u.query.state).toHaveLength(24);
        });

        it('should save state in session', function () {
          const u = uri.parse(url, true);

          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toHaveLength(24);
          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toEqual(u.query.state);
          expect(
            request.session['oauth2:www.example.com'].state.state
          ).toBeUndefined();
        });
      }); // that redirects to service provider with state set to boolean false

      describe('that redirects to service provider with other data in session', function () {
        let request, url;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .redirect(function (u) {
                url = u;
                resolve(null);
              })
              .request(function (req) {
                req.session = {};
                req.session['oauth2:www.example.com'] = {};
                req.session['oauth2:www.example.com'].foo = 'bar';
                request = req;
              })
              .authenticate();
          });
        });

        it('should be redirected', function () {
          const u = uri.parse(url, true);
          expect(u.query.state).toHaveLength(24);
        });

        it('should save state in session', function () {
          const u = uri.parse(url, true);

          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toHaveLength(24);
          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toEqual(u.query.state);
          expect(
            request.session['oauth2:www.example.com'].state.state
          ).toBeUndefined();
        });

        it('should preserve other data in session', function () {
          expect(request.session['oauth2:www.example.com'].foo).toEqual('bar');
        });
      }); // that redirects to service provider with other data in session

      describe('that errors due to lack of session support in app', function () {
        let err;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .error(function (e) {
                err = e;
                resolve(null);
              })
              .request(function () {})
              .authenticate();
          });
        });

        it('should error', function () {
          expect(err).toBeInstanceOf(Error);
          expect(err.message).toEqual(
            'OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?'
          );
        });
      }); // that errors due to lack of session support in app
    }); // issuing authorization request

    describe('issuing authorization request to authorization server using authorization endpoint that has query parameters including state', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL:
            'https://www.example.com/oauth2/authorize?foo=bar&state=baz',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: true
        },
        function () {}
      );

      describe('that redirects to service provider', function () {
        let request, url;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .redirect(function (u) {
                url = u;
                resolve(null);
              })
              .request(function (req) {
                req.session = {};
                request = req;
              })
              .authenticate();
          });
        });

        it('should be redirected', function () {
          const u = uri.parse(url, true);
          expect(u.query.foo).toEqual('bar');
          expect(u.query.state).toHaveLength(24);
        });

        it('should save state in session', function () {
          const u = uri.parse(url, true);

          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toHaveLength(24);
          expect(
            request.session['oauth2:www.example.com'].state.handle
          ).toEqual(u.query.state);
        });
      }); // that redirects to service provider
    }); // issuing authorization request to authorization server using authorization endpoint that has query parameters including state

    describe('processing response to authorization request', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: true
        },
        function (accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
            return done(new Error('incorrect accessToken argument'));
          }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(new Error('incorrect refreshToken argument'));
          }
          if (typeof profile !== 'object') {
            return done(new Error('incorrect profile argument'));
          }
          if (Object.keys(profile).length !== 0) {
            return done(new Error('incorrect profile argument'));
          }

          return done(null, { id: '1234' }, { message: 'Hello' });
        }
      );

      strategy._oauth2.getOAuthAccessToken = function (
        code,
        options,
        callback
      ) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') {
          return callback(new Error('incorrect code argument'));
        }
        if (options.grant_type !== 'authorization_code') {
          return callback(new Error('incorrect options.grant_type argument'));
        }
        if (
          options.redirect_uri !==
          'https://www.example.net/auth/example/callback'
        ) {
          return callback(new Error('incorrect options.redirect_uri argument'));
        }

        return callback(
          null,
          '2YotnFZFEjr1zCsicMWpAA',
          'tGzv3JOkF0XG5Qx2TlKWIA',
          { token_type: 'example' }
        );
      };

      describe('that was approved', function () {
        let request, user, info;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .success(function (u, i) {
                user = u;
                info = i;
                resolve(null);
              })
              .request(function (req) {
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
                req.session = {};
                req.session['oauth2:www.example.com'] = {};
                req.session['oauth2:www.example.com']['state'] = {
                  handle: 'DkbychwKu8kBaJoLE5yeR5NK'
                };

                request = req;
              })
              .authenticate();
          });
        });

        it('should supply user', function () {
          expect(user.id).toEqual('1234');
        });

        it('should supply info', function () {
          expect(info.message).toEqual('Hello');
          expect(info.state).toBeUndefined();
        });

        it('should remove state from session', function () {
          expect(request.session['oauth2:www.example.com']).toBeUndefined();
        });
      }); // that was approved

      describe('that was approved with state', function () {
        let request, user, info;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .success(function (u, i) {
                user = u;
                info = i;
                resolve(null);
              })
              .request(function (req) {
                req.query = {};

                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
                req.session = {};
                req.session['oauth2:www.example.com'] = {};
                req.session['oauth2:www.example.com']['state'] = {
                  handle: 'DkbychwKu8kBaJoLE5yeR5NK',
                  state: { returnTo: '/somewhere' }
                };
                request = req;
              })
              .authenticate();
          });
        });

        it('should supply user', function () {
          expect(user.id).toEqual('1234');
        });

        it('should supply info', function () {
          expect(info.message).toEqual('Hello');
          expect(info.state).toEqual({ returnTo: '/somewhere' });
        });

        it('should remove state from session', function () {
          expect(request.session['oauth2:www.example.com']).toBeUndefined();
        });
      }); // that was approved with state

      describe('that was approved with other data in the session', function () {
        let request, user, info;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .success(function (u, i) {
                user = u;
                info = i;
                resolve(null);
              })
              .request(function (req) {
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
                req.session = {};
                req.session['oauth2:www.example.com'] = {};
                req.session['oauth2:www.example.com']['state'] = {
                  handle: 'DkbychwKu8kBaJoLE5yeR5NK'
                };
                req.session['oauth2:www.example.com'].foo = 'bar';

                request = req;
              })
              .authenticate();
          });
        });

        it('should supply user', function () {
          expect(user.id).toEqual('1234');
        });

        it('should supply info', function () {
          expect(info.message).toEqual('Hello');
        });

        it('should preserve other data from session', function () {
          expect(
            request.session['oauth2:www.example.com'].state
          ).toBeUndefined();
          expect(request.session['oauth2:www.example.com'].foo).toEqual('bar');
        });
      }); // that was approved with other data in the session

      describe('that fails due to state being invalid', function () {
        let request, info, status;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .fail(function (i, s) {
                info = i;
                status = s;
                resolve(null);
              })
              .request(function (req) {
                request = req;

                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK-WRONG';
                req.session = {};
                req.session['oauth2:www.example.com'] = {};
                req.session['oauth2:www.example.com']['state'] = {
                  handle: 'DkbychwKu8kBaJoLE5yeR5NK'
                };
              })
              .authenticate();
          });
        });

        it('should supply info', function () {
          expect(info.message).toEqual('Invalid authorization request state.');
        });

        it('should supply status', function () {
          expect(status).toEqual(403);
        });

        it('should remove state from session', function () {
          expect(request.session['oauth2:www.example.com']).toBeUndefined();
        });
      }); // that fails due to state being invalid

      describe('that fails due to provider-specific state not found in session', function () {
        let info, status;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .fail(function (i, s) {
                info = i;
                status = s;
                resolve(null);
              })
              .request(function (req) {
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
                req.session = {};
              })
              .authenticate();
          });
        });

        it('should supply info', function () {
          expect(info.message).toEqual(
            'Unable to verify authorization request state.'
          );
        });

        it('should supply status', function () {
          expect(status).toEqual(403);
        });
      }); // that fails due to state not found in session

      describe('that fails due to provider-specific state lacking state value', function () {
        let info, status;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .fail(function (i, s) {
                info = i;
                status = s;
                resolve(null);
              })
              .request(function (req) {
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
                req.session = {};
                req.session['oauth2:www.example.com'] = {};
              })
              .authenticate();
          });
        });

        it('should supply info', function () {
          expect(info.message).toEqual(
            'Unable to verify authorization request state.'
          );
        });

        it('should supply status', function () {
          expect(status).toEqual(403);
        });
      }); // that fails due to provider-specific state lacking state value

      describe('that errors due to lack of session support in app', function () {
        let err;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .error(function (e) {
                err = e;
                resolve(null);
              })
              .request(function (req) {
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              })
              .authenticate();
          });
        });

        it('should error', function () {
          expect(err).toBeInstanceOf(Error);
          expect(err.message).toEqual(
            'OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?'
          );
        });
      }); // that errors due to lack of session support in app
    }); // processing response to authorization request
  }); // using default session state store

  describe('using default session state store through store option with session key option', function () {
    const strategy = new OAuth2Strategy(
      {
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        store: true,
        sessionKey: 'oauth2:example'
      },
      function (accessToken, refreshToken, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
          return done(new Error('incorrect accessToken argument'));
        }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
          return done(new Error('incorrect refreshToken argument'));
        }
        if (typeof profile !== 'object') {
          return done(new Error('incorrect profile argument'));
        }
        if (Object.keys(profile).length !== 0) {
          return done(new Error('incorrect profile argument'));
        }

        return done(null, { id: '1234' }, { message: 'Hello' });
      }
    );

    strategy._oauth2.getOAuthAccessToken = function (code, options, callback) {
      if (code !== 'SplxlOBeZQQYbYS6WxSbIA') {
        return callback(new Error('incorrect code argument'));
      }
      if (options.grant_type !== 'authorization_code') {
        return callback(new Error('incorrect options.grant_type argument'));
      }
      if (
        options.redirect_uri !== 'https://www.example.net/auth/example/callback'
      ) {
        return callback(new Error('incorrect options.redirect_uri argument'));
      }

      return callback(
        null,
        '2YotnFZFEjr1zCsicMWpAA',
        'tGzv3JOkF0XG5Qx2TlKWIA',
        { token_type: 'example' }
      );
    };

    describe('issuing authorization request', function () {
      describe('that redirects to service provider', function () {
        let request, url;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .redirect(function (u) {
                url = u;
                resolve(null);
              })
              .request(function (req) {
                request = req;
                req.session = {};
              })
              .authenticate();
          });
        });

        it('should be redirected', function () {
          const u = uri.parse(url, true);
          expect(u.query.state).toHaveLength(24);
        });

        it('should save state in session', function () {
          const u = uri.parse(url, true);

          expect(request.session['oauth2:example'].state.handle).toHaveLength(
            24
          );
          expect(request.session['oauth2:example'].state.handle).toEqual(
            u.query.state
          );
          expect(request.session['oauth2:example'].state.state).toBeUndefined();
        });
      }); // that redirects to service provider
    }); // issuing authorization request

    describe('processing response to authorization request', function () {
      describe('that was approved', function () {
        let request, user, info;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .success(function (u, i) {
                user = u;
                info = i;
                resolve(null);
              })
              .request(function (req) {
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
                req.session = {};
                req.session['oauth2:example'] = {};
                req.session['oauth2:example']['state'] = {
                  handle: 'DkbychwKu8kBaJoLE5yeR5NK'
                };

                request = req;
              })
              .authenticate();
          });
        });

        it('should supply user', function () {
          expect(user.id).toEqual('1234');
        });

        it('should supply info', function () {
          expect(info.message).toEqual('Hello');
        });

        it('should remove state from session', function () {
          expect(request.session['oauth2:example']).toBeUndefined();
        });
      }); // that was approved
    }); // processing response to authorization request
  }); // using default session state store with session key option
});
