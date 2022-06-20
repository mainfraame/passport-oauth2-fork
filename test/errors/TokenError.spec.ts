import { TokenError } from '../../src';

describe('TokenError', function () {
  describe('constructed without a message', function () {
    const err = new TokenError();

    it('should have default properties', function () {
      expect(err.message).toBeUndefined();
      expect(err.code).toEqual('invalid_request');
      expect(err.uri).toBeUndefined();
      expect(err.status).toEqual(500);
    });

    it('should format correctly', function () {
      expect(err.toString().indexOf('TokenError')).toEqual(0);
    });
  });

  describe('constructed with a message', function () {
    const err = new TokenError('Mismatched return URI');

    it('should have default properties', function () {
      expect(err.message).toEqual('Mismatched return URI');
      expect(err.code).toEqual('invalid_request');
      expect(err.uri).toBeUndefined();
      expect(err.status).toEqual(500);
    });

    it('should format correctly', function () {
      expect(err.toString()).toEqual('TokenError: Mismatched return URI');
    });
  });

  describe('constructed with a message, code, uri and status', function () {
    const err = new TokenError(
      'Unsupported grant type: foo',
      'unsupported_grant_type',
      'http://www.example.com/oauth/help',
      501
    );

    it('should have default properties', function () {
      expect(err.message).toEqual('Unsupported grant type: foo');
      expect(err.code).toEqual('unsupported_grant_type');
      expect(err.uri).toEqual('http://www.example.com/oauth/help');
      expect(err.status).toEqual(501);
    });

    it('should format correctly', function () {
      expect(err.toString()).toEqual('TokenError: Unsupported grant type: foo');
    });
  });
});
