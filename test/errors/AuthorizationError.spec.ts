import { AuthorizationError } from '../../src';

describe('AuthorizationError', function () {
  describe('constructed without a message', function () {
    const err = new AuthorizationError();

    it('should have default properties', function () {
      expect(err.message).toBeUndefined();
      expect(err.code).toEqual('server_error');
      expect(err.uri).toBeUndefined();
      expect(err.status).toEqual(500);
    });

    it('should format correctly', function () {
      //expect(err.toString()).toEqual('AuthorizationError');
      expect(err.toString().indexOf('AuthorizationError')).toEqual(0);
    });
  });

  describe('constructed with a message', function () {
    const err = new AuthorizationError('Invalid return URI');

    it('should have default properties', function () {
      expect(err.message).toEqual('Invalid return URI');
      expect(err.code).toEqual('server_error');
      expect(err.uri).toBeUndefined();
      expect(err.status).toEqual(500);
    });

    it('should format correctly', function () {
      expect(err.toString()).toEqual('AuthorizationError: Invalid return URI');
    });
  });

  describe('constructed with a message and access_denied code', function () {
    const err = new AuthorizationError('Access denied', 'access_denied');

    it('should have default properties', function () {
      expect(err.message).toEqual('Access denied');
      expect(err.code).toEqual('access_denied');
      expect(err.uri).toBeUndefined();
      expect(err.status).toEqual(403);
    });
  });

  describe('constructed with a message and server_error code', function () {
    const err = new AuthorizationError('Server error', 'server_error');

    it('should have default properties', function () {
      expect(err.message).toEqual('Server error');
      expect(err.code).toEqual('server_error');
      expect(err.uri).toBeUndefined();
      expect(err.status).toEqual(502);
    });
  });

  describe('constructed with a message and temporarily_unavailable code', function () {
    const err = new AuthorizationError(
      'Temporarily unavailable',
      'temporarily_unavailable'
    );

    it('should have default properties', function () {
      expect(err.message).toEqual('Temporarily unavailable');
      expect(err.code).toEqual('temporarily_unavailable');
      expect(err.uri).toBeUndefined();
      expect(err.status).toEqual(503);
    });
  });

  describe('constructed with a message, code, uri and status', function () {
    const err = new AuthorizationError(
      'Unsupported response type: foo',
      'unsupported_response_type',
      'http://www.example.com/oauth/help',
      501
    );

    it('should have default properties', function () {
      expect(err.message).toEqual('Unsupported response type: foo');
      expect(err.code).toEqual('unsupported_response_type');
      expect(err.uri).toEqual('http://www.example.com/oauth/help');
      expect(err.status).toEqual(501);
    });

    it('should format correctly', function () {
      expect(err.toString()).toEqual(
        'AuthorizationError: Unsupported response type: foo'
      );
    });
  });
});
