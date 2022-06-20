import chai from 'chai';
import passport from 'chai-passport-strategy';

import { OAuth2Strategy } from '../src';

chai.use(passport);

describe('OAuth2Strategy - custom state', function () {
  describe('with custom state store that accepts meta argument', function () {
    class CustomStore {
      store(req, meta, cb) {
        if (req.url === '/error') {
          return cb(new Error('something went wrong storing state'));
        }
        if (req.url === '/exception') {
          throw new Error('something went horribly wrong storing state');
        }

        if (req.url !== '/me') {
          return cb(new Error('incorrect req argument'));
        }
        if (
          meta.authorizationURL !== 'https://www.example.com/oauth2/authorize'
        ) {
          return cb(new Error('incorrect meta.authorizationURL argument'));
        }
        if (meta.tokenURL !== 'https://www.example.com/oauth2/token') {
          return cb(new Error('incorrect meta.tokenURL argument'));
        }
        if (meta.clientID !== 'ABC123') {
          return cb(new Error('incorrect meta.clientID argument'));
        }

        req.customStoreStoreCalled = req.customStoreStoreCalled
          ? req.customStoreStoreCalled++
          : 1;
        return cb(null, 'foos7473');
      }

      verify(req, state, meta, cb) {
        if (req.url === '/error') {
          return cb(new Error('something went wrong verifying state'));
        }
        if (req.url === '/exception') {
          throw new Error('something went horribly wrong verifying state');
        }

        if (req.url !== '/auth/example/callback') {
          return cb(new Error('incorrect req argument'));
        }
        if (state !== 'foos7473') {
          return cb(new Error('incorrect state argument'));
        }
        if (
          meta.authorizationURL !== 'https://www.example.com/oauth2/authorize'
        ) {
          return cb(new Error('incorrect meta.authorizationURL argument'));
        }
        if (meta.tokenURL !== 'https://www.example.com/oauth2/token') {
          return cb(new Error('incorrect meta.tokenURL argument'));
        }
        if (meta.clientID !== 'ABC123') {
          return cb(new Error('incorrect meta.clientID argument'));
        }

        req.customStoreVerifyCalled = req.customStoreVerifyCalled
          ? req.customStoreVerifyCalled++
          : 1;
        return cb(null, true);
      }
    }

    describe('issuing authorization request', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: new CustomStore()
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
                request = req;
                req.url = '/me';
              })
              .authenticate();
          });
        });

        it('should be redirected', function () {
          expect(url).toEqual(
            'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&state=foos7473&client_id=ABC123'
          );
        });

        it('should serialize state using custom store', function () {
          expect(request.customStoreStoreCalled).toEqual(1);
        });
      }); // that redirects to service provider

      describe('that errors due to custom store supplying error', function () {
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
                req.url = '/error';
              })
              .authenticate();
          });
        });

        it('should error', function () {
          expect(err).toBeInstanceOf(Error);
          expect(err.message).toEqual('something went wrong storing state');
        });
      }); // that errors due to custom store supplying error

      describe('that errors due to custom store throwing error', function () {
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
                req.url = '/exception';
              })
              .authenticate();
          });
        });

        it('should error', function () {
          expect(err).toBeInstanceOf(Error);
          expect(err.message).toEqual(
            'something went horribly wrong storing state'
          );
        });
      }); // that errors due to custom store throwing error
    }); // issuing authorization request

    describe('processing response to authorization request', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: new CustomStore()
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
                request = req;

                req.url = '/auth/example/callback';
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'foos7473';
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

        it('should verify state using custom store', function () {
          expect(request.customStoreVerifyCalled).toEqual(1);
        });
      }); // that was approved

      describe('that errors due to custom store supplying error', function () {
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
                req.url = '/error';
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'foos7473';
              })
              .authenticate();
          });
        });

        it('should error', function () {
          expect(err).toBeInstanceOf(Error);
          expect(err.message).toEqual('something went wrong verifying state');
        });
      }); // that errors due to custom store supplying error

      describe('that errors due to custom store throwing error', function () {
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
                req.url = '/exception';
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'foos7473';
              })
              .authenticate();
          });
        });

        it('should error', function () {
          expect(err).toBeInstanceOf(Error);
          expect(err.message).toEqual(
            'something went horribly wrong verifying state'
          );
        });
      }); // that errors due to custom store throwing error
    }); // processing response to authorization request
  }); // with custom state store that accepts meta argument

  describe('with custom state store that accepts meta argument and supplies state', function () {
    function CustomStore() {}

    CustomStore.prototype.verify = function (req, state, meta, cb) {
      req.customStoreVerifyCalled = req.customStoreVerifyCalled
        ? req.customStoreVerifyCalled++
        : 1;
      return cb(null, true, { returnTo: 'http://www.example.com/' });
    };

    describe('processing response to authorization request', function () {
      describe('that was approved without info', function () {
        const strategy = new OAuth2Strategy(
          {
            authorizationURL: 'https://www.example.com/oauth2/authorize',
            tokenURL: 'https://www.example.com/oauth2/token',
            clientID: 'ABC123',
            clientSecret: 'secret',
            callbackURL: 'https://www.example.net/auth/example/callback',
            store: new CustomStore()
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

            return done(null, { id: '1234' });
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
            return callback(
              new Error('incorrect options.redirect_uri argument')
            );
          }

          return callback(
            null,
            '2YotnFZFEjr1zCsicMWpAA',
            'tGzv3JOkF0XG5Qx2TlKWIA',
            { token_type: 'example' }
          );
        };

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
                request = req;

                req.url = '/auth/example/callback';
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'foos7473';
              })
              .authenticate();
          });
        });

        it('should supply user', function () {
          expect(user.id).toEqual('1234');
        });

        it('should supply info with state', function () {
          expect(Object.keys(info)).toHaveLength(1);

          expect(info.state.returnTo).toEqual('http://www.example.com/');
        });

        it('should verify state using custom store', function () {
          expect(request.customStoreVerifyCalled).toEqual(1);
        });
      }); // that was approved without info

      describe('that was approved with info', function () {
        const strategy = new OAuth2Strategy(
          {
            authorizationURL: 'https://www.example.com/oauth2/authorize',
            tokenURL: 'https://www.example.com/oauth2/token',
            clientID: 'ABC123',
            clientSecret: 'secret',
            callbackURL: 'https://www.example.net/auth/example/callback',
            store: new CustomStore()
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
            return callback(
              new Error('incorrect options.redirect_uri argument')
            );
          }

          return callback(
            null,
            '2YotnFZFEjr1zCsicMWpAA',
            'tGzv3JOkF0XG5Qx2TlKWIA',
            { token_type: 'example' }
          );
        };

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
                request = req;

                req.url = '/auth/example/callback';
                req.query = {};
                req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
                req.query.state = 'foos7473';
              })
              .authenticate();
          });
        });

        it('should supply user', function () {
          expect(user.id).toEqual('1234');
        });

        it('should supply info with state', function () {
          expect(Object.keys(info)).toHaveLength(2);
          expect(info.message).toEqual('Hello');

          expect(info.state.returnTo).toEqual('http://www.example.com/');
        });

        it('should verify state using custom store', function () {
          expect(request.customStoreVerifyCalled).toEqual(1);
        });
      }); // that was approved with info
    }); // processing response to authorization request
  }); // with custom state store that accepts meta argument and supplies state
});
