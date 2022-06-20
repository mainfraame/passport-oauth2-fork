import { InternalOAuthError } from '../../src';

describe('InternalOAuthError', function () {
  describe('constructed without a message', function () {
    const err = new InternalOAuthError();

    it('should format correctly', function () {
      expect(err.toString()).toEqual('InternalOAuthError');
    });
  });

  describe('constructed with a message', function () {
    const err = new InternalOAuthError('oops');

    it('should format correctly', function () {
      expect(err.toString()).toEqual('InternalOAuthError: oops');
    });
  });

  describe('constructed with a message and error', function () {
    const err = new InternalOAuthError('oops', new Error('something is wrong'));

    it('should format correctly', function () {
      expect(err.toString()).toEqual('Error: something is wrong');
    });
  });

  describe('constructed with a message and object with status code and data', function () {
    const err = new InternalOAuthError('oops', {
      statusCode: 401,
      data: 'invalid OAuth credentials'
    });

    it('should format correctly', function () {
      expect(err.toString()).toEqual(
        'InternalOAuthError: oops (status: 401 data: invalid OAuth credentials)'
      );
    });
  });
});
