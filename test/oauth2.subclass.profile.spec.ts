import chai from 'chai';
import passport from 'chai-passport-strategy';

import { OAuth2Strategy } from '../src';

chai.use(passport);

describe('OAuth2Strategy - subclass profile', function () {
  describe('that overrides userProfile', function () {
    class FooOAuth2Strategy extends OAuth2Strategy {
      userProfile(accessToken, done) {
        if (accessToken === '666') {
          return done(new Error('something went wrong loading user profile'));
        }

        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
          return done(new Error('incorrect accessToken argument'));
        }

        return done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
      }
    }

    describe('fetching user profile', function () {
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
          if (profile.username != 'jaredhanson') {
            return done(new Error('incorrect profile argument'));
          }

          return done(
            null,
            { id: '1234', username: profile.username },
            { message: 'Hello' }
          );
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
            .authenticate();
        });
      });

      it('should supply user', function () {
        expect(user.id).toEqual('1234');
        expect(user.username).toEqual('jaredhanson');
      });

      it('should supply info', function () {
        expect(info.message).toEqual('Hello');
      });
    }); // fetching user profile

    describe('error fetching user profile', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function (accessToken, refreshToken, profile, done) {
          return done(new Error('verify callback should not be called'));
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

        return callback(null, '666', 'tGzv3JOkF0XG5Qx2TlKWIA', {
          token_type: 'example'
        });
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
        expect(err.message).toEqual(
          'something went wrong loading user profile'
        );
      });
    }); // error fetching user profile

    describe('skipping user profile due to skipUserProfile option set to true', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: true
        },
        function (accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
            return done(new Error('incorrect accessToken argument'));
          }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(new Error('incorrect refreshToken argument'));
          }
          if (profile !== undefined) {
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
            .authenticate();
        });
      });

      it('should supply user', function () {
        expect(user.id).toEqual('1234');
      });

      it('should supply info', function () {
        expect(info.message).toEqual('Hello');
      });
    }); // skipping user profile due to skipUserProfile option set to true

    describe('not skipping user profile due to skipUserProfile returning false', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: function () {
            return false;
          }
        },
        function (accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
            return done(new Error('incorrect accessToken argument'));
          }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(new Error('incorrect refreshToken argument'));
          }
          if (profile.username != 'jaredhanson') {
            return done(new Error('incorrect profile argument'));
          }

          return done(
            null,
            { id: '1234', username: profile.username },
            { message: 'Hello' }
          );
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
            .authenticate();
        });
      });

      it('should supply user', function () {
        expect(user.id).toEqual('1234');
        expect(user.username).toEqual('jaredhanson');
      });

      it('should supply info', function () {
        expect(info.message).toEqual('Hello');
      });
    }); // not skipping user profile due to skipUserProfile returning false

    describe('skipping user profile due to skipUserProfile returning true', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: function () {
            return true;
          }
        },
        function (accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
            return done(new Error('incorrect accessToken argument'));
          }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(new Error('incorrect refreshToken argument'));
          }
          if (profile !== undefined) {
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
            .authenticate();
        });
      });

      it('should supply user', function () {
        expect(user.id).toEqual('1234');
      });

      it('should supply info', function () {
        expect(info.message).toEqual('Hello');
      });
    }); // skipping user profile due to skipUserProfile returning true

    describe('not skipping user profile due to skipUserProfile asynchronously returning false', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: function (accessToken, done) {
            if (accessToken != '2YotnFZFEjr1zCsicMWpAA') {
              return done(new Error('incorrect token argument'));
            }

            return done(null, false);
          }
        },
        function (accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
            return done(new Error('incorrect accessToken argument'));
          }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(new Error('incorrect refreshToken argument'));
          }
          if (profile.username != 'jaredhanson') {
            return done(new Error('incorrect profile argument'));
          }

          return done(
            null,
            { id: '1234', username: profile.username },
            { message: 'Hello' }
          );
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
            .authenticate();
        });
      });

      it('should supply user', function () {
        expect(user.id).toEqual('1234');
        expect(user.username).toEqual('jaredhanson');
      });

      it('should supply info', function () {
        expect(info.message).toEqual('Hello');
      });
    }); // not skipping user profile due to skipUserProfile asynchronously returning false

    describe('skipping user profile due to skipUserProfile asynchronously returning true', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: function (accessToken, done) {
            if (accessToken != '2YotnFZFEjr1zCsicMWpAA') {
              return done(new Error('incorrect token argument'));
            }

            return done(null, true);
          }
        },
        function (accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
            return done(new Error('incorrect accessToken argument'));
          }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(new Error('incorrect refreshToken argument'));
          }
          if (profile !== undefined) {
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
            .authenticate();
        });
      });

      it('should supply user', function () {
        expect(user.id).toEqual('1234');
      });

      it('should supply info', function () {
        expect(info.message).toEqual('Hello');
      });
    }); // skipping user profile due to skipUserProfile asynchronously returning true

    describe('error due to skipUserProfile asynchronously returning error', function () {
      const strategy = new FooOAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: function (accessToken, done) {
            return done(new Error('something went wrong'));
          }
        },
        function (accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
            return done(new Error('incorrect accessToken argument'));
          }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(new Error('incorrect refreshToken argument'));
          }
          if (profile !== undefined) {
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
        expect(err.message).toEqual('something went wrong');
      });
    }); // error due to skipUserProfile asynchronously returning error
  }); // that overrides userProfile
});
