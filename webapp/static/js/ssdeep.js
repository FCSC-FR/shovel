/*
 * Copyright (C) 2015 Hu Wenshuo
 * SPDX-License-Identifier: MIT
 * From https://github.com/cloudtracer/ssdeep.js/blob/master/ssdeep.js
 *
 * ssdeep fuzzyhash are computed by backend.
 * This only implements the distance computation.
 */

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

// Based on https://github.com/hiddentao/fast-levenshtein
function levenshtein (str1, str2) {
  // base cases
  if (str1 === str2) return 0
  if (str1.length === 0) return str2.length
  if (str2.length === 0) return str1.length

  // two rows
  const prevRow = new Array(str2.length + 1)
  let nextCol
  let j

  // initialise previous row
  for (let i = 0; i < prevRow.length; ++i) {
    prevRow[i] = i
  }

  // calculate current row distance from previous row
  for (let i = 0; i < str1.length; ++i) {
    nextCol = i + 1

    for (j = 0; j < str2.length; ++j) {
      const curCol = nextCol

      // substution
      nextCol = prevRow[j] + (str1.charAt(i) === str2.charAt(j) ? 0 : 1)
      // insertion
      let tmp = curCol + 1
      if (nextCol > tmp) {
        nextCol = tmp
      }
      // deletion
      tmp = prevRow[j + 1] + 1
      if (nextCol > tmp) {
        nextCol = tmp
      }

      // copy current col value into previous (in preparation for next iteration)
      prevRow[j] = curCol
    }

    // copy last col value into previous (in preparation for next iteration)
    prevRow[j] = nextCol
  }
  return nextCol
}

function matchScore (s1, s2) {
  const e = levenshtein(s1, s2)
  const r = 1 - e / Math.max(s1.length, s2.length)
  return r * 100
}

function ssdeepCompare (d1, d2) {
  const b1 = B64.indexOf(d1.charAt(0))
  const b2 = B64.indexOf(d2.charAt(0))
  if (b1 > b2) return ssdeepCompare(d2, d1)

  if (Math.abs(b1 - b2) > 1) {
    return 0
  } else if (b1 === b2) {
    return matchScore(d1.split(':')[1], d2.split(':')[1])
  } else {
    return matchScore(d1.split(':')[2], d2.split(':')[1])
  }
}

export { ssdeepCompare }
