const uuidv4 = require('uuid').v4;
const sortStoreList = require('./sort-list');
const { queryOperatorsKeys, checkClaimValueByRule } = require('./check-claims');

/*
store
{
  "c68892eb-2fdf-45e5-9d0d-6e4592640eca": {
    "expAt": 1578009600000,
    "type": "all",
    "claims": {
      "userId": {
        "query": "eq",
        "value": "sometestuserid",
      },
    }
  },
  "b637ce58-8d55-44f4-a07d-9d77ad2043f8": {
    "expAt": 1578009600000,
    "type": "refresh",
    "claims": {
      "userId": {
        "query": "eq",
        "value": "someuserid",
      },
      "iat": {
        "query": "gte",
        "value": 1578009600000, // '03-01-2020'
      },
    }
  },
  "30106816-99a4-499a-bced-c1b91717efa9": {
    "expAt": 1578009600000,
    "type": "access",
    "claims": {
      "iat": {
        "query": "gte",
        "value": 1669939200000, // '2022-12-02'
      }
    },
  },
}
*/
/*
rule 1:
{
  "type": "refresh",
  "claims": {
    "userId": {
      "eq": "someuserid",
    },
    "iat": {
      "gte": 1578009600000,
    },
  }
}
rule 2:
{
  "type": "access",
  "claims": {
    "iat": {
      "gte": 1669939200000, // '2022-12-02'
    }
  }
}
rule 3:
{
  "type": "all",
  "claims": {
    "userId": {
      "eq": "sometestuserid",
    },
  }
}
*/

// move to global config
const tokenexpAt = {
  refresh: 365 * 24 * 60 * 60 * 1000, // 365 days in ms
  access: 1 * 60 * 60 * 1000, // 1 hour in ms
};

// const TOKEN_TYPES = ['refresh', 'access'];

class RevokeTokenApi {
  constructor() {
    this.store = {};
  }

  addRule(rule) {
    const { type, claims: addingClaims } = rule;

    const id = uuidv4();
    // rule expiration time
    const expAt = Date.now() + (tokenexpAt[type] || tokenexpAt.refresh);

    const claims = {};
    Object.entries(addingClaims).forEach(([tokenClaim, queryValue]) => {
      const claimQueryOptions = Object.entries(queryValue);

      const [query, value] = claimQueryOptions
        .find(([queryKey]) => queryOperatorsKeys.includes(queryKey));

      claims[tokenClaim] = {
        query,
        value,
      };
    });

    const newStoreRule = {
      [id]: {
        id,
        type,
        expAt,
        claims,
      },
    };

    this.store = sortStoreList({ ...this.store, ...newStoreRule });

    // sync rules with other nodes

    return id;
  }

  /**
   * Remove rule from store by rule id
   * @param {string} id Rule ID
   */
  removeRule(id) {
    const { [id]: ruleByID, ...restRules } = this.store;

    this.store = restRules;

    // or
    // delete this.store[id];

    // sync rules with other nodes
  }

  isRevoked(decodedData) {
    const ruleList = Object.entries(this.store);
    const decodedDataKeys = Object.keys(decodedData);

    const isRevokedByRule = ruleList.some(([ruleID, rule]) => {
      const { type, expAt, claims } = rule;

      // remove rule if rule expired
      if (Date.now() > expAt) {
        this.removeRule(ruleID);
        return false;
      }

      if (type !== decodedData.type && type !== 'all') {
        return false;
      }
      return decodedDataKeys.every((dataClaim) => {
        const ruleClaimValue = claims[dataClaim];
        const claimValue = decodedData[dataClaim];

        return checkClaimValueByRule(ruleClaimValue, claimValue);
      });
    });

    return isRevokedByRule;
  }
}

module.exports = {
  RevokeTokenApi,
};
