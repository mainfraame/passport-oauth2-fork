import uri from 'url';

import chai from 'chai';
import passport from 'chai-passport-strategy';

import { OAuth2Strategy } from '../src';

chai.use(passport);

jest.mock('crypto', () => ({
  // @ts-ignore
  ...jest.requireActual('crypto'),
  pseudoRandomBytes: function (len) {
    if (len !== 32) {
      throw new Error('xyz');
    }
    return new Buffer([
      116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187,
      186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121
    ]);
  }
}));

describe('OAuth2Strategy - pkce state', function () {
  describe('with store and PKCE true transformation method', function () {
    const strategy = new OAuth2Strategy(
      {
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        store: true,
        pkce: true
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
      if (
        options.code_verifier !== 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      ) {
        return callback(
          new Error('incorrect options.verifier loaded from session')
        );
      }

      return callback(
        null,
        '2YotnFZFEjr1zCsicMWpAA',
        'tGzv3JOkF0XG5Qx2TlKWIA',
        { token_type: 'example' }
      );
    };

    describe('handling a request to be redirected for authorization', function () {
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
        expect(u.query.code_challenge).toHaveLength(43);
        expect(u.query.code_challenge).toEqual(
          'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        );
        expect(u.query.code_challenge_method).toEqual('S256');
      });

      it('should save verifier in session', function () {
        const u = uri.parse(url, true);
        expect(
          request.session['oauth2:www.example.com'].state.handle
        ).toHaveLength(24);
        expect(request.session['oauth2:www.example.com'].state.handle).toEqual(
          u.query.state
        );
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toHaveLength(43);
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toEqual('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        expect(
          request.session['oauth2:www.example.com'].state.state
        ).toBeUndefined();
      });
    });

    describe('handling a request to be redirected for authorization with state', function () {
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
        expect(u.query.code_challenge).toHaveLength(43);
        expect(u.query.code_challenge).toEqual(
          'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        );
        expect(u.query.code_challenge_method).toEqual('S256');
      });

      it('should save verifier in session', function () {
        const u = uri.parse(url, true);
        expect(
          request.session['oauth2:www.example.com'].state.handle
        ).toHaveLength(24);
        expect(request.session['oauth2:www.example.com'].state.handle).toEqual(
          u.query.state
        );
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toHaveLength(43);
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toEqual('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        expect(request.session['oauth2:www.example.com'].state.state).toEqual({
          returnTo: '/somewhere'
        });
      });
    });

    describe('handling a request to be redirected for authorization with state as boolean true', function () {
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
        expect(u.query.code_challenge).toHaveLength(43);
        expect(u.query.code_challenge).toEqual(
          'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        );
        expect(u.query.code_challenge_method).toEqual('S256');
      });

      it('should save verifier in session', function () {
        const u = uri.parse(url, true);
        expect(
          request.session['oauth2:www.example.com'].state.handle
        ).toHaveLength(24);
        expect(request.session['oauth2:www.example.com'].state.handle).toEqual(
          u.query.state
        );
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toHaveLength(43);
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toEqual('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        expect(request.session['oauth2:www.example.com'].state.state).toEqual(
          true
        );
      });
    });

    describe('handling a request to be redirected for authorization with state as boolean false', function () {
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
        expect(u.query.code_challenge).toHaveLength(43);
        expect(u.query.code_challenge).toEqual(
          'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        );
        expect(u.query.code_challenge_method).toEqual('S256');
      });

      it('should save verifier in session', function () {
        const u = uri.parse(url, true);
        expect(
          request.session['oauth2:www.example.com'].state.handle
        ).toHaveLength(24);
        expect(request.session['oauth2:www.example.com'].state.handle).toEqual(
          u.query.state
        );
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toHaveLength(43);
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toEqual('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        expect(
          request.session['oauth2:www.example.com'].state.state
        ).toBeUndefined();
      });
    });

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
              request = req;
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com'].foo = 'bar';
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
        expect(request.session['oauth2:www.example.com'].state.handle).toEqual(
          u.query.state
        );
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toHaveLength(43);
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toEqual('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
      });

      it('should preserve other data in session', function () {
        expect(request.session['oauth2:www.example.com'].foo).toEqual('bar');
      });
    }); // that redirects to service provider with other data in session

    describe('processing response to authorization request', function () {
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

              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com']['state'] = {
                handle: 'DkbychwKu8kBaJoLE5yeR5NK',
                code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
              };
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

      it('should remove state with verifier from session', function () {
        expect(request.session['oauth2:www.example.com']).toBeUndefined();
      });
    });

    describe('processing response to authorization request with state', function () {
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

              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com']['state'] = {
                handle: 'DkbychwKu8kBaJoLE5yeR5NK',
                code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
                state: { returnTo: '/somewhere' }
              };
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

      it('should remove state with verifier from session', function () {
        expect(request.session['oauth2:www.example.com']).toBeUndefined();
      });
    });

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
              request = req;

              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com']['state'] = {
                handle: 'DkbychwKu8kBaJoLE5yeR5NK',
                code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
              };
              req.session['oauth2:www.example.com'].foo = 'bar';
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
        expect(request.session['oauth2:www.example.com'].state).toBeUndefined();
        expect(request.session['oauth2:www.example.com'].foo).toEqual('bar');
      });
    }); // that was approved with other data in the session

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
  });

  describe('with store and PKCE plain transformation method', function () {
    const strategy = new OAuth2Strategy(
      {
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        store: true,
        pkce: 'plain'
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
      if (
        options.code_verifier !== 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      ) {
        return callback(
          new Error('incorrect options.verifier loaded from session')
        );
      }

      return callback(
        null,
        '2YotnFZFEjr1zCsicMWpAA',
        'tGzv3JOkF0XG5Qx2TlKWIA',
        { token_type: 'example' }
      );
    };

    describe('handling a request to be redirected for authorization', function () {
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
        expect(u.query.code_challenge).toHaveLength(43);
        expect(u.query.code_challenge).toEqual(
          'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        );
        expect(u.query.code_challenge_method).toEqual('plain');
      });

      it('should save verifier in session', function () {
        const u = uri.parse(url, true);
        expect(
          request.session['oauth2:www.example.com'].state.handle
        ).toHaveLength(24);
        expect(request.session['oauth2:www.example.com'].state.handle).toEqual(
          u.query.state
        );
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toHaveLength(43);
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toEqual('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
      });
    });

    describe('processing response to authorization request', function () {
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

              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com']['state'] = {
                handle: 'DkbychwKu8kBaJoLE5yeR5NK',
                code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
              };
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

      it('should remove state with verifier from session', function () {
        expect(request.session['oauth2:www.example.com']).toBeUndefined();
      });
    });
  });

  describe('with store and PKCE S256 transformation method', function () {
    const strategy = new OAuth2Strategy(
      {
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        store: true,
        pkce: 'S256'
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
      if (
        options.code_verifier !== 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      ) {
        return callback(
          new Error('incorrect options.verifier loaded from session')
        );
      }

      return callback(
        null,
        '2YotnFZFEjr1zCsicMWpAA',
        'tGzv3JOkF0XG5Qx2TlKWIA',
        { token_type: 'example' }
      );
    };

    describe('handling a request to be redirected for authorization', function () {
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
        expect(u.query.code_challenge).toHaveLength(43);
        expect(u.query.code_challenge).toEqual(
          'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        );
        expect(u.query.code_challenge_method).toEqual('S256');
      });

      it('should save verifier in session', function () {
        const u = uri.parse(url, true);
        expect(
          request.session['oauth2:www.example.com'].state.handle
        ).toHaveLength(24);
        expect(request.session['oauth2:www.example.com'].state.handle).toEqual(
          u.query.state
        );
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toHaveLength(43);
        expect(
          request.session['oauth2:www.example.com'].state.code_verifier
        ).toEqual('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
      });
    });

    describe('processing response to authorization request', function () {
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

              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com']['state'] = {
                handle: 'DkbychwKu8kBaJoLE5yeR5NK',
                code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
              };
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

      it('should remove state with verifier from session', function () {
        expect(request.session['oauth2:www.example.com']).toBeUndefined();
      });
    });
  });

  describe('with exceptions', function () {
    describe('with store and unknown encoding method', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: true,
          pkce: 'unknown'
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
              req.session = {};
            })
            .authenticate();
        });
      });

      it('should error', function () {
        expect(err.message).toEqual(
          'Unsupported code verifier transformation method: unknown'
        );
      });
    });

    describe('with store and unknown verifier', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: true,
          pkce: 'S256'
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

      let info;

      beforeAll(function () {
        return new Promise((resolve) => {
          chai.passport
            .use(strategy)
            .fail(function (i) {
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
            })
            .authenticate();
        });
      });

      it('should not supply info', function () {
        expect(info).toBeUndefined();
      });
    });

    describe('store and that fails due to state being invalid', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: true,
          pkce: 'S256'
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
                handle: 'DkbychwKu8kBaJoLE5yeR5NK',
                code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
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

    describe('store and that fails due to provider-specific state not found in session', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: true,
          pkce: 'S256'
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

    describe('store and that fails due to provider-specific state lacking state value', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: true,
          pkce: 'S256'
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

    describe('store and that errors due to lack of session support in app', function () {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          store: true,
          pkce: 'S256'
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
  });
});
