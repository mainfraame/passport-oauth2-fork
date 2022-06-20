import chai from 'chai';
import passport from 'chai-passport-strategy';

import { InternalOAuthError, OAuth2Strategy } from '../src';

chai.use(passport);

describe('OAuth2Strategy - subclass', function () {
  describe('that overrides authorizationParams', function () {
    class FooOAuth2Strategy extends OAuth2Strategy {
      authorizationParams(options) {
        return { prompt: options.prompt };
      }
    }

    describe('issuing authorization request that redirects to service provider', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function (accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
            return done(new Error('incorrect accessToken argument'));
          }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(new Error('incorrect refreshToken argument'));
          }

          return done(null, { id: '1234' }, { message: 'Hello' });
        }
      );

      describe('with prompt', function () {
        let url;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .redirect(function (u) {
                url = u;
                resolve(null);
              })
              .request(function () {})
              .authenticate({ prompt: 'mobile' });
          });
        });

        it('should be redirected', function () {
          expect(url).toEqual(
            'https://www.example.com/oauth2/authorize?prompt=mobile&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123'
          );
        });
      });

      describe('with scope and prompt', function () {
        let url;

        beforeAll(function () {
          return new Promise((resolve) => {
            chai.passport
              .use(strategy)
              .redirect(function (u) {
                url = u;
                resolve(null);
              })
              .request(function () {})
              .authenticate({ scope: 'email', prompt: 'mobile' });
          });
        });

        it('should be redirected', function () {
          expect(url).toEqual(
            'https://www.example.com/oauth2/authorize?prompt=mobile&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=email&client_id=ABC123'
          );
        });
      }); // with scope and prompt
    }); // issuing authorization request that redirects to service provider
  }); // that overrides authorizationParams

  describe('that overrides tokenParams', function () {
    class FooOAuth2Strategy extends OAuth2Strategy {
      tokenParams(options) {
        return { type: options.type };
      }
    }

    describe('processing response to authorization request that was approved', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function (accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
            return done(new Error('incorrect accessToken argument'));
          }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(new Error('incorrect refreshToken argument'));
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
        if (options.type !== 'web_server') {
          return callback(new Error('incorrect options.type argument'));
        }

        callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', {
          token_type: 'example'
        });
      };

      let user, info;

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
            })
            .authenticate({ type: 'web_server' });
        });
      });

      it('should supply user', function () {
        expect(user.id).toEqual('1234');
      });

      it('should supply info', function () {
        expect(info.message).toEqual('Hello');
      });
    }); // processing response to authorization request that was approved
  }); // that overrides tokenParams

  describe('that overrides parseErrorResponse', function () {
    class FooOAuth2Strategy extends OAuth2Strategy {
      parseErrorResponse(body, status?) {
        if (status === 500) {
          throw new Error('something went horribly wrong');
        }

        const e = new Error('Custom OAuth error');
        e['body'] = body;
        e['status'] = status;
        return e;
      }
    }

    describe('and supplies error', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function (accessToken, refreshToken, profile, done) {
          if (
            accessToken === '2YotnFZFEjr1zCsicMWpAA' &&
            refreshToken === 'tGzv3JOkF0XG5Qx2TlKWIA'
          ) {
            return done(null, { id: '1234' }, { message: 'Hello' });
          }
          return done(null, false);
        }
      );

      strategy._oauth2.getOAuthAccessToken = function (
        code,
        options,
        callback
      ) {
        return callback({ statusCode: 400, data: 'Invalid code' });
      };

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
            })
            .authenticate();
        });
      });

      it('should error', function () {
        expect(err).toBeInstanceOf(Error);
        expect(err.message).toEqual('Custom OAuth error');
        expect(err.body).toEqual('Invalid code');
        expect(err.status).toEqual(400);
      });
    }); // and supplies error

    describe('and throws exception', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function (accessToken, refreshToken, profile, done) {
          if (
            accessToken === '2YotnFZFEjr1zCsicMWpAA' &&
            refreshToken === 'tGzv3JOkF0XG5Qx2TlKWIA'
          ) {
            return done(null, { id: '1234' }, { message: 'Hello' });
          }
          return done(null, false);
        }
      );

      strategy._oauth2.getOAuthAccessToken = function (
        code,
        options,
        callback
      ) {
        return callback({ statusCode: 500, data: 'Invalid code' });
      };

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
            })
            .authenticate();
        });
      });

      it('should error', function () {
        expect(err).toBeInstanceOf(InternalOAuthError);
        expect(err.message).toEqual('Failed to obtain access token');
        expect(err.oauthError.statusCode).toEqual(500);
        expect(err.oauthError.data).toEqual('Invalid code');
      });
    }); // and throws exception
  }); // that overrides parseErrorResponse
});
