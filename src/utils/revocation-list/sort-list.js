/**
 * sorting rules for fast find revoked token in rule list
 * @param {Object} store
 */
const sortStoreList = (store) => {
  // more logic for sorting?
  const sortedList = Object.entries(store)
    .sort((ruleA, ruleB) => {
      const [, rulePropsA] = ruleA;
      const [, rulePropsB] = ruleB;

      const ruleClaimsSizeA = Object.keys(rulePropsA.claims).length;
      const ruleClaimsSizeB = Object.keys(rulePropsB.claims).length;

      return ruleClaimsSizeA - ruleClaimsSizeB;
    });

  return Object.fromEntries(sortedList);
};

module.exports = sortStoreList;
