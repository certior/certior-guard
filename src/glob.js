'use strict';
// Minimal fnmatch — shell-glob match over capability names (only `*` is used by
// the shipped rules, but `?` and `[…]` are supported for user-authored ones).

function globToRegExp(pattern) {
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') re += '.*';
    else if (c === '?') re += '.';
    else if (c === '[') {
      let j = i + 1;
      if (pattern[j] === '!') j++;
      if (pattern[j] === ']') j++;
      while (j < pattern.length && pattern[j] !== ']') j++;
      if (j >= pattern.length) { re += '\\['; } else {
        let stuff = pattern.slice(i + 1, j).replace(/\\/g, '\\\\');
        if (stuff[0] === '!') stuff = '^' + stuff.slice(1);
        re += '[' + stuff + ']';
        i = j;
      }
    } else re += c.replace(/[.^$+{}()|\\/]/g, '\\$&');
  }
  return new RegExp('^' + re + '$');
}

function fnmatch(name, pattern) {
  return globToRegExp(pattern).test(name);
}

module.exports = { fnmatch };
