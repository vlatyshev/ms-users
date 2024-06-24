const queryOperators = {
  eq: (a, b) => a === b,
  ne: (a, b) => a !== b,
  gt: (a, b) => a > b,
  gte: (a, b) => a >= b,
  lt: (a, b) => a < b,
  lte: (a, b) => a <= b,
  regex: (a, b) => {
    if (typeof b !== 'string' && !(b instanceof RegExp)) {
      return true;
    }
    const valueAsRegEx = new RegExp(b);

    return valueAsRegEx.test(String(a));
  },
  sw: (a, b) => {
    if (typeof b !== 'string') {
      return true;
    }
    return String(a).startsWith(b);
  },
};

const queryOperatorsKeys = Object.keys(queryOperators);

/**
 * Check rule claims with decoded token claims by comparison query operators
 * @param {Object} ruleClaim
 * @param {string} ruleClaim.query
 * @param {string | number | RegExp} ruleClaim.value
 * @param {*} decodedClaimValue
 * @returns {boolean}
 */
const checkClaimValueByRule = (ruleClaim, decodedClaimValue) => {
  if (ruleClaim === undefined) {
    return true;
  }
  const { query, value } = ruleClaim;
  const comparisonFunc = queryOperators[query];

  if (comparisonFunc === undefined) {
    return true;
  }
  return comparisonFunc(decodedClaimValue, value);
};

module.exports = {
  queryOperatorsKeys,
  checkClaimValueByRule,
};
