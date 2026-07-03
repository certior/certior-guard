'use strict';
// Tiny ANSI helper — colours only when stdout is a TTY and NO_COLOR is unset.
const on = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (s) => (on ? `\x1b[${code}m${s}\x1b[0m` : String(s));

module.exports = {
  red: c('31'), green: c('32'), yellow: c('33'),
  cyan: c('36'), dim: c('90'), bold: c('1'),
};
