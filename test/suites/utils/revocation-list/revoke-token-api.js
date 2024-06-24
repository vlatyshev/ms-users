const assert = require('assert');

const { RevokeTokenApi } = require('../../../../src/utils/revocation-list/revoke-token-api');

describe('#revoke-token-api', function suite() {
  it('add rule', () => {
    const revokeApi = new RevokeTokenApi();

    const rule = {
      type: 'refresh',
      claims: {
        userId: {
          eq: 'testuserid',
        },
        exp: {
          lte: 1578009600000, // '03-01-2020'
        },
      },
    };

    const id = revokeApi.addRule(rule);

    assert.ok(typeof id === 'string');
    assert.ok(revokeApi.store[id]);
    assert.deepStrictEqual(revokeApi.store[id], {
      id,
      type: 'refresh',
      expAt: revokeApi.store[id].expAt,
      claims: {
        userId: {
          query: 'eq',
          value: 'testuserid',
        },
        exp: {
          query: 'lte',
          value: 1578009600000, // '03-01-2020'
        },
      },
    });
  });

  it('remove rule', () => {
    const revokeApi = new RevokeTokenApi();

    const rule = {
      type: 'all',
      claims: {
        userId: {
          regex: /.*/,
        },
      },
    };

    const id = revokeApi.addRule(rule);
    assert.ok(revokeApi.store[id]);

    revokeApi.removeRule(id);
    assert.ok(revokeApi.store[id] === undefined);
    assert.deepStrictEqual(revokeApi.store, {});
  });

  describe('check token by rules', () => {
    it('should token revoked', () => {
      const revokeApi = new RevokeTokenApi();

      const rule = {
        type: 'access',
        claims: {
          userId: {
            eq: 'testuserid',
          },
          iat: {
            gte: 1578009600000, // 03.01.2020
          },
        },
      };
      const rule2 = {
        type: 'refresh',
        claims: {
          exp: {
            lte: 1669939200000, // 02.12.2022
          },
        },
      };
      const decodedData = {
        userId: 'someuserid',
        type: 'refresh',
        iat: 1576926000000, // 21.12.2019
        exp: 1618939200000, // 20.04.2021
      };

      revokeApi.addRule(rule);
      revokeApi.addRule(rule2);

      const isTokenRevoked = revokeApi.isRevoked(decodedData);
      assert.ok(isTokenRevoked);
    });

    it('should token not revoked', () => {
      const revokeApi = new RevokeTokenApi();

      const rule = {
        type: 'access',
        claims: {
          userId: {
            eq: 'testuserid',
          },
          iat: {
            gte: 1578009600000, // 03.01.2020
          },
        },
      };
      const rule2 = {
        type: 'refresh',
        claims: {
          exp: {
            lte: 1669939200000, // 02.12.2022
          },
        },
      };
      const rule3 = {
        type: 'all',
        claims: {
          exp: {
            lte: 1558939200000, // 27.05.2019
          },
        },
      };
      const decodedTokenData = {
        userId: 'someuserid',
        type: 'access',
        iat: 1618790400000, // 19.04.2021
        exp: 1618939200000, // 20.04.2021
      };

      revokeApi.addRule(rule);
      revokeApi.addRule(rule2);
      revokeApi.addRule(rule3);

      const isTokenRevoked = revokeApi.isRevoked(decodedTokenData);
      assert.strictEqual(isTokenRevoked, false);
    });
  });
});
