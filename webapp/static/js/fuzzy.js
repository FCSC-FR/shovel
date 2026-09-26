/*
 * Copyright (C) 2019 idealista <labs@idealista.com>
 * SPDX-License-Identifier: Apache-2.0
 * From https://github.com/idealista/tlsh-js/
 *
 * Fuzzyhashes are computed by backend.
 * This only implements the distance computation.
 */

const BIT_PAIRS_DIFF_TABLE_SIZE = 256
const BIT_PAIRS_DIFF_TABLE = generateDefaultBitPairsTable()

function generateDefaultBitPairsTable () {
  const result = new Array(BIT_PAIRS_DIFF_TABLE_SIZE)

  for (let i = 0; i < result.length; i++) {
    result[i] = new Array(BIT_PAIRS_DIFF_TABLE_SIZE)
  }

  for (let i = 0; i < BIT_PAIRS_DIFF_TABLE_SIZE; i++) {
    for (let j = 0; j < BIT_PAIRS_DIFF_TABLE_SIZE; j++) {
      let x = i
      let y = j
      let diff = 0

      for (let z = 0; z < 4; z++) {
        const d = Math.abs((x % 4) - (y % 4))

        if (d === 3) {
          diff += d * 2
        } else {
          diff += d
        }

        if (z < 3) {
          x = Math.floor(x / 4)
          y = Math.floor(y / 4)
        }
      }

      result[i][j] = diff
    }
  }

  return result
}

function swap (data) {
  let result = ((data & 0xf0) >> 4) & 0x0f
  result |= ((data & 0x0f) << 4) & 0xf0
  return result
}

function calculateModularDifference (
  initialPosition,
  finalPosition,
  circularQueueSize
) {
  const internalDistance = Math.abs(finalPosition - initialPosition)
  const externalDistance = circularQueueSize - internalDistance
  return Math.min(internalDistance, externalDistance)
}

class Body {
  constructor (value) {
    this.value = value
  }

  calculateDifference (other) {
    let diff = 0
    for (let i = 0; i < this.value.length; i++) {
      diff += BIT_PAIRS_DIFF_TABLE[this.value[i]][other.value[i]]
    }
    return diff
  }
}

class Checksum {
  constructor (checksumData) {
    this.checksumData = checksumData
  }

  calculateDifference (other) {
    const areEquals = (a, b) =>
      a.length === b.length &&
      a.every((element, index) => element === b[index])
    if (!areEquals(this.checksumData, other.checksumData)) return 1
    return 0
  }
}

class LValue {
  constructor (value) {
    this.value = value
  }

  calculateDifference (other) {
    const RANGE_LVALUE = 256
    const ldiff = calculateModularDifference(
      this.value,
      other.value,
      RANGE_LVALUE
    )
    if (ldiff === 0) {
      return 0
    }
    if (ldiff === 1) {
      return 1
    }
    return ldiff * 12
  }
}

class Digest {
  constructor (checksum, lValue, q, body) {
    this.lValue = lValue
    this.q = q
    this.checksum = checksum
    this.body = body
  }

  calculateDifference (other, lengthDiff) {
    let difference = 0
    if (lengthDiff) {
      difference += this.lValue.calculateDifference(other.lValue)
    }
    difference += this.q.calculateDifference(other.q)
    difference += this.checksum.calculateDifference(other.checksum)
    difference += this.body.calculateDifference(other.body)
    return difference
  }
}

class Q {
  constructor (value) {
    this.value = value
  }

  getQLo () {
    return this.value & 0x0f
  }

  getQHi () {
    return (this.value & 0xf0) >> 4
  }

  calculateDifference (other) {
    const RANGE_QRATIO = 16

    let diff = 0

    const q1diff = calculateModularDifference(
      this.getQLo(),
      other.getQLo(),
      RANGE_QRATIO
    )

    if (q1diff <= 1) {
      diff += q1diff
    } else {
      diff += (q1diff - 1) * 12
    }

    const q2diff = calculateModularDifference(
      this.getQHi(),
      other.getQHi(),
      RANGE_QRATIO
    )

    if (q2diff <= 1) {
      diff += q2diff
    } else {
      diff += (q2diff - 1) * 12
    }

    return diff
  }
}

function buildDigestWithHash (hash) {
  // Parse hex
  const digestData = new Array(hash.length / 2)
  for (let i = 0; i < hash.length; i += 2) {
    digestData[i / 2] = parseInt(hash.substring(i, i + 2), 16)
  }

  // Parse fields
  let i = 0
  const checksum = new Checksum([swap(digestData[i++])])
  const lValue = new LValue([swap(digestData[i++])])
  const q = new Q([swap(digestData[i++])])
  const rawBodyData = digestData.slice(i, digestData.length)
  const bodyData = new Array(rawBodyData.length)
  for (let j = 0; j < rawBodyData.length; j++) {
    bodyData[j] = rawBodyData[rawBodyData.length - 1 - j]
  }
  const body = new Body(bodyData)

  return new Digest(checksum, lValue, q, body)
}

/**
 * @param {String} d1 First hex digest starting with T1
 * @param {String} d2 Second hex digest starting with T1
 * @returns Distance, 0 if same
 */
function fuzzyCompare (d1, d2) {
  if (d1.startsWith('T1') && d2.startsWith('T1')) {
    return buildDigestWithHash(d2).calculateDifference(buildDigestWithHash(d1), true)
  } else {
    return 10000
  }
}

export { fuzzyCompare }
